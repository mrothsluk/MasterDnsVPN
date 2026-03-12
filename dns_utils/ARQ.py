# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from dns_utils.DNS_ENUMS import Packet_Type


@dataclass
class _PendingControlPacket:
    packet_type: int
    sequence_num: int
    ack_type: int
    payload: bytes
    priority: int
    retries: int = 0
    current_rto: float = 0.8
    time: float = 0.0
    create_time: float = 0.0


class ARQ:
    _active_tasks = set()

    CONTROL_ACK_PAIRS = {
        Packet_Type.STREAM_SYN: Packet_Type.STREAM_SYN_ACK,
        Packet_Type.STREAM_FIN: Packet_Type.STREAM_FIN_ACK,
        Packet_Type.STREAM_RST: Packet_Type.STREAM_RST_ACK,
        Packet_Type.SOCKS5_SYN: Packet_Type.SOCKS5_SYN_ACK,
        Packet_Type.STREAM_KEEPALIVE: Packet_Type.STREAM_KEEPALIVE_ACK,
        Packet_Type.STREAM_WINDOW_UPDATE: Packet_Type.STREAM_WINDOW_UPDATE_ACK,
        Packet_Type.STREAM_PROBE: Packet_Type.STREAM_PROBE_ACK,
        Packet_Type.SOCKS5_CONNECT_FAIL: Packet_Type.SOCKS5_CONNECT_FAIL_ACK,
        Packet_Type.SOCKS5_RULESET_DENIED: Packet_Type.SOCKS5_RULESET_DENIED_ACK,
        Packet_Type.SOCKS5_NETWORK_UNREACHABLE: Packet_Type.SOCKS5_NETWORK_UNREACHABLE_ACK,
        Packet_Type.SOCKS5_HOST_UNREACHABLE: Packet_Type.SOCKS5_HOST_UNREACHABLE_ACK,
        Packet_Type.SOCKS5_CONNECTION_REFUSED: Packet_Type.SOCKS5_CONNECTION_REFUSED_ACK,
        Packet_Type.SOCKS5_TTL_EXPIRED: Packet_Type.SOCKS5_TTL_EXPIRED_ACK,
        Packet_Type.SOCKS5_COMMAND_UNSUPPORTED: Packet_Type.SOCKS5_COMMAND_UNSUPPORTED_ACK,
        Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED: Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        Packet_Type.SOCKS5_AUTH_FAILED: Packet_Type.SOCKS5_AUTH_FAILED_ACK,
        Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE: Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    }

    class _DummyLogger:
        def debug(self, *args, **kwargs):
            pass

        def info(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

    def __init__(
        self,
        stream_id,
        session_id,
        enqueue_tx_cb,
        reader,
        writer,
        mtu,
        logger=None,
        window_size: int = 600,
        rto: float = 0.8,
        max_rto: float = 1.5,
        is_socks: bool = False,
        initial_data: bytes = b"",
        enqueue_control_tx_cb=None,
        enable_control_reliability: bool = False,
        control_rto: float = 0.8,
        control_max_rto: float = 2.5,
        control_max_retries: int = 15,
    ):
        self.stream_id = stream_id
        self.session_id = session_id
        self.enqueue_tx = enqueue_tx_cb
        self.reader = reader
        self.writer = writer
        self.mtu = mtu

        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_buf = {}
        self.rcv_buf = {}

        self.last_activity = time.monotonic()
        self.closed = False
        self.close_reason = "Unknown"
        self.logger = logger or self._DummyLogger()

        self._fin_sent = False
        self._fin_received = False
        self._fin_acked = False
        self._fin_seq_sent = None
        self._fin_seq_received = None

        self._rst_received = False
        self._rst_sent = False
        self._rst_acked = False
        self._rst_seq_sent = None
        self._rst_seq_received = None
        self._close_time = None

        self._local_write_closed = False
        self._remote_write_closed = False

        self.rto = rto
        self.max_rto = max_rto

        self.window_size = window_size
        self.limit = max(50, int(self.window_size * 0.8))
        self.window_not_full = asyncio.Event()
        self.window_not_full.set()
        self._write_lock = asyncio.Lock()
        self.state = "OPEN"  # OPEN, HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSING, TIME_WAIT, RESET, CLOSED

        self.is_socks = is_socks
        self.initial_data = initial_data
        self.socks_connected = asyncio.Event()
        if not self.is_socks:
            self.socks_connected.set()

        # Control-plane reliability (optional): keeps ARQ data-path intact
        # while allowing control packets to be retried/acked with sequence numbers.
        self.enqueue_control_tx = enqueue_control_tx_cb
        self.enable_control_reliability = bool(enable_control_reliability)
        self.control_rto = float(control_rto)
        self.control_max_rto = float(control_max_rto)
        self.control_max_retries = int(control_max_retries)
        self.control_snd_buf: Dict[Tuple[int, int], _PendingControlPacket] = {}
        self._control_ack_map = dict(self.CONTROL_ACK_PAIRS)
        self._control_reverse_ack_map = {v: k for k, v in self._control_ack_map.items()}
        try:
            sock = writer.get_extra_info("socket")
            if sock and sock.fileno() != -1:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError, Exception):
            pass

        try:
            loop = asyncio.get_running_loop()
            self.io_task = loop.create_task(self._io_loop())
            self.rtx_task = loop.create_task(self._retransmit_loop())

            ARQ._active_tasks.add(self.io_task)
            ARQ._active_tasks.add(self.rtx_task)
            self.io_task.add_done_callback(ARQ._active_tasks.discard)
            self.rtx_task.add_done_callback(ARQ._active_tasks.discard)
        except RuntimeError:
            self.io_task = None
            self.rtx_task = None

    async def _io_loop(self):
        _read = self.reader.read
        _enqueue = self.enqueue_tx
        _monotonic = time.monotonic
        _mtu = self.mtu
        _limit = self.limit

        reset_required = False
        graceful_eof = False
        error_reason = None

        try:
            if self.is_socks and self.initial_data:
                offset = 0
                total_len = len(self.initial_data)
                while offset < total_len:
                    chunk = self.initial_data[offset : offset + _mtu]
                    sn = self.snd_nxt
                    self.snd_nxt = (sn + 1) % 65536

                    self.snd_buf[sn] = {
                        "data": chunk,
                        "time": _monotonic(),
                        "create_time": _monotonic(),
                        "retries": 0,
                        "current_rto": self.rto,
                        "is_socks_syn": True,
                    }
                    await _enqueue(3, self.stream_id, sn, chunk, is_socks_syn=True)
                    offset += _mtu

            await self.socks_connected.wait()

            while not self.closed:
                await self.window_not_full.wait()

                if self._fin_received:
                    self.close_reason = "FIN Received, No More Data to Send"
                    break

                try:
                    raw_data = await _read(_mtu)
                except ConnectionResetError:
                    error_reason = "Local App Reset Connection (Dropped)"
                    reset_required = True
                    break
                except Exception as e:
                    error_reason = f"Read Error: {e}"
                    reset_required = True
                    break

                if not raw_data:
                    error_reason = "Local App Closed Connection (EOF)"
                    graceful_eof = True
                    break

                self.last_activity = _monotonic()
                sn = self.snd_nxt
                self.snd_nxt = (sn + 1) % 65536

                self.snd_buf[sn] = {
                    "data": raw_data,
                    "time": self.last_activity,
                    "create_time": _monotonic(),
                    "retries": 0,
                    "current_rto": self.rto,
                    "is_socks_syn": False,
                }

                if len(self.snd_buf) >= _limit:
                    self.window_not_full.clear()

                await _enqueue(3, self.stream_id, sn, raw_data)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.debug(f"Stream {self.stream_id} IO loop error: {e}")
        finally:
            if self.closed:
                return

            if reset_required:
                await self.abort(reason=error_reason or "Local reset/error")
                return

            if self._fin_received:
                wait_deadline = time.monotonic() + 180.0
                while (
                    self.snd_buf
                    and time.monotonic() < wait_deadline
                    and not self.closed
                ):
                    await asyncio.sleep(0.05)

                if self.snd_buf and not self.closed:
                    await self.abort(
                        reason="Remote FIN but local send buffer did not drain"
                    )
                    return

                if not self.closed:
                    await self._initiate_graceful_close(
                        reason="Remote FIN fully handled"
                    )
                return

            if graceful_eof:
                await self._initiate_graceful_close(reason=error_reason or "Local EOF")

    async def _initiate_graceful_close(self, reason="Graceful close"):
        if self.closed:
            return

        self.close_reason = reason

        deadline = time.monotonic() + 300.0
        while self.snd_buf and time.monotonic() < deadline and not self.closed:
            await asyncio.sleep(0.05)

        if self.closed:
            return

        if self.snd_buf:
            await self.abort(reason=f"{reason} but send buffer did not drain")
            return

        await self.close(reason=reason, send_fin=True)

    async def _try_finalize_remote_eof(self):
        if (
            self.closed
            or self._remote_write_closed
            or not self._fin_received
            or self._fin_seq_received is None
            or self.rcv_nxt != self._fin_seq_received
        ):
            return

        self._remote_write_closed = True

        try:
            if (
                self.writer
                and hasattr(self.writer, "can_write_eof")
                and self.writer.can_write_eof()
            ):
                self.writer.write_eof()
                try:
                    await self.writer.drain()
                except Exception:
                    pass
        except Exception:
            pass

        try:
            await self.enqueue_tx(
                0,
                self.stream_id,
                self._fin_seq_received,
                b"",
                is_fin_ack=True,
            )
        except Exception:
            pass

        if self._fin_sent and self._fin_acked and not self.snd_buf:
            await self.close(reason="Both FINs fully acknowledged")

    async def _retransmit_loop(self):
        """Separate lightweight task for RTO checks."""
        _sleep = asyncio.sleep
        try:
            while not self.closed:
                await _sleep(self.rto / 2.0)
                if self.closed:
                    break

                try:
                    await self.check_retransmits()
                except Exception as e:
                    self.logger.debug(
                        f"Retransmit check error on stream {self.stream_id}: {e}"
                    )

        except asyncio.CancelledError:
            pass

    async def receive_data(self, sn, data):
        if self.closed:
            return

        self.last_activity = time.monotonic()

        diff = (sn - self.rcv_nxt) % 65536
        if diff >= 32768:
            await self.enqueue_tx(0, self.stream_id, sn, b"", is_ack=True)
            return

        if diff > self.window_size:
            return

        if sn not in self.rcv_buf:
            self.rcv_buf[sn] = data

        has_written = False
        _write = self.writer.write
        _pop = self.rcv_buf.pop

        data_to_write = []

        while self.rcv_nxt in self.rcv_buf:
            try:
                data_to_write.append(_pop(self.rcv_nxt))
                has_written = True
                self.rcv_nxt = (self.rcv_nxt + 1) % 65536
            except Exception as e:
                await self.abort(reason=f"RCV Buffer Error: {e}")
                return

        if has_written:
            try:
                async with self._write_lock:
                    _write(b"".join(data_to_write))
                    await self.writer.drain()
            except Exception as e:
                await self.abort(reason=f"Writer Error: {e}")
                return

        await self.enqueue_tx(0, self.stream_id, sn, b"", is_ack=True)

        await self._try_finalize_remote_eof()

    async def receive_ack(self, sn):
        self.last_activity = time.monotonic()

        if self.snd_buf.pop(sn, None) is not None:
            if len(self.snd_buf) < self.limit:
                self.window_not_full.set()

    async def receive_rst_ack(self, sn):
        self.last_activity = time.monotonic()

        if self._rst_seq_sent is not None and sn == self._rst_seq_sent:
            self._rst_acked = True

        if self.enable_control_reliability:
            self._mark_control_acked(Packet_Type.STREAM_RST_ACK, sn)

    def _norm_sn(self, sn: int) -> int:
        return int(sn) & 0xFFFF

    async def _send_control_frame(
        self,
        packet_type: int,
        sequence_num: int,
        payload: bytes = b"",
        priority: int = 0,
        is_retransmit: bool = False,
    ) -> bool:
        ptype = int(packet_type)
        sn = self._norm_sn(sequence_num)
        data = payload or b""

        # Preferred path: direct control callback with explicit packet_type.
        if self.enqueue_control_tx:
            await self.enqueue_control_tx(
                int(priority),
                self.stream_id,
                sn,
                ptype,
                data,
                is_retransmit=is_retransmit,
            )
            return True

        # Backward-compatible fallback using existing enqueue_tx flag API.
        if ptype == Packet_Type.STREAM_FIN:
            await self.enqueue_tx(int(priority), self.stream_id, sn, data, is_fin=True)
            return True
        if ptype == Packet_Type.STREAM_FIN_ACK:
            await self.enqueue_tx(0, self.stream_id, sn, data, is_fin_ack=True)
            return True
        if ptype == Packet_Type.STREAM_RST:
            await self.enqueue_tx(0, self.stream_id, sn, data, is_rst=True)
            return True
        if ptype == Packet_Type.STREAM_RST_ACK:
            await self.enqueue_tx(0, self.stream_id, sn, data, is_rst_ack=True)
            return True
        if ptype == Packet_Type.STREAM_DATA_ACK:
            await self.enqueue_tx(0, self.stream_id, sn, data, is_ack=True)
            return True
        if ptype == Packet_Type.SOCKS5_SYN:
            await self.enqueue_tx(
                int(priority), self.stream_id, sn, data, is_socks_syn=True
            )
            return True

        # STREAM_SYN / STREAM_SYN_ACK and some control types need explicit control callback.
        return False

    def _track_control_packet(
        self,
        packet_type: int,
        sequence_num: int,
        ack_type: int,
        payload: bytes,
        priority: int,
    ) -> None:
        key = (int(packet_type), self._norm_sn(sequence_num))
        if key in self.control_snd_buf:
            return

        now = time.monotonic()
        self.control_snd_buf[key] = _PendingControlPacket(
            packet_type=int(packet_type),
            sequence_num=self._norm_sn(sequence_num),
            ack_type=int(ack_type),
            payload=payload or b"",
            priority=int(priority),
            retries=0,
            current_rto=self.control_rto,
            time=now,
            create_time=now,
        )

    async def send_control_packet(
        self,
        packet_type: int,
        sequence_num: int,
        payload: bytes = b"",
        priority: int = 0,
        track_for_ack: bool = True,
        ack_type: Optional[int] = None,
    ) -> bool:
        ptype = int(packet_type)
        sn = self._norm_sn(sequence_num)

        sent = await self._send_control_frame(
            packet_type=ptype,
            sequence_num=sn,
            payload=payload,
            priority=priority,
            is_retransmit=False,
        )
        if not sent:
            return False

        if not (self.enable_control_reliability and track_for_ack):
            return True

        expected_ack = (
            int(ack_type) if ack_type is not None else self._control_ack_map.get(ptype)
        )
        if expected_ack is None:
            return True

        self._track_control_packet(
            packet_type=ptype,
            sequence_num=sn,
            ack_type=expected_ack,
            payload=payload,
            priority=priority,
        )
        return True

    def _mark_control_acked(self, ack_packet_type: int, sequence_num: int) -> bool:
        ack_ptype = int(ack_packet_type)
        sn = self._norm_sn(sequence_num)

        origin_ptype = self._control_reverse_ack_map.get(ack_ptype)
        if origin_ptype is None:
            return self.control_snd_buf.pop((ack_ptype, sn), None) is not None

        if self.control_snd_buf.pop((origin_ptype, sn), None) is not None:
            return True

        # Compatibility fallback for peers that may ACK non-seq control with sn=0.
        if self.control_snd_buf.pop((origin_ptype, 0), None) is not None:
            return True

        return False

    async def receive_control_ack(
        self, ack_packet_type: int, sequence_num: int
    ) -> bool:
        self.last_activity = time.monotonic()

        ack_ptype = int(ack_packet_type)
        sn = self._norm_sn(sequence_num)

        if ack_ptype == Packet_Type.STREAM_FIN_ACK:
            if self._fin_seq_sent is not None and sn == self._fin_seq_sent:
                self._fin_acked = True
        elif ack_ptype == Packet_Type.STREAM_RST_ACK:
            if self._rst_seq_sent is not None and sn == self._rst_seq_sent:
                self._rst_acked = True

        return self._mark_control_acked(ack_ptype, sn)

    async def _check_control_retransmits(self, now: float) -> None:
        if not self.control_snd_buf:
            return

        for key, info in list(self.control_snd_buf.items()):
            if (
                info.create_time + 120.0 <= now
                and info.retries >= self.control_max_retries
            ):
                self.control_snd_buf.pop(key, None)
                continue

            if now - info.time < info.current_rto:
                continue

            sent = await self._send_control_frame(
                packet_type=info.packet_type,
                sequence_num=info.sequence_num,
                payload=info.payload,
                priority=info.priority,
                is_retransmit=True,
            )

            if not sent:
                # Cannot resend this control type on legacy callback path.
                self.control_snd_buf.pop(key, None)
                continue

            info.time = now
            info.retries += 1
            info.current_rto = min(self.control_max_rto, info.current_rto * 1.5)

    async def check_retransmits(self):
        if self.closed:
            return

        now = time.monotonic()

        if now - self.last_activity > 300.0:
            await self.abort(reason="Stream Inactivity Timeout (Dead)")
            return

        items_to_resend = []
        _append = items_to_resend.append

        for sn, info in list(self.snd_buf.items()):
            if info["create_time"] + 120.0 <= now and info["retries"] >= 100:
                await self.abort(reason=f"Max retransmissions exceeded for sn={sn}")
                return

            if now - info["time"] >= info["current_rto"]:
                items_to_resend.append(
                    (sn, info["data"], info.get("is_socks_syn", False))
                )
                info["time"] = now
                info["retries"] += 1
                dynamic_max = max(
                    self.max_rto, 15.0 if info["retries"] > 10 else self.max_rto
                )
                info["current_rto"] = min(dynamic_max, info["current_rto"] * 1.5)

        _enqueue = self.enqueue_tx
        _sid = self.stream_id

        for sn, data, is_socks_syn in items_to_resend:
            if is_socks_syn:
                await _enqueue(1, _sid, sn, data, is_socks_syn=True)
            else:
                await _enqueue(1, _sid, sn, data, is_resend=True)

        if self.enable_control_reliability:
            await self._check_control_retransmits(now)

    async def abort(self, reason="Abort", send_rst=True):
        if self.closed:
            return

        if send_rst and not self._rst_sent and not self._rst_received:
            self._rst_sent = True
            if self._rst_seq_sent is None:
                self._rst_seq_sent = self.snd_nxt

            try:
                if self.enable_control_reliability:
                    await self.send_control_packet(
                        packet_type=Packet_Type.STREAM_RST,
                        sequence_num=self._rst_seq_sent,
                        payload=b"",
                        priority=0,
                        track_for_ack=True,
                        ack_type=Packet_Type.STREAM_RST_ACK,
                    )
                else:
                    await self.enqueue_tx(
                        0,
                        self.stream_id,
                        self._rst_seq_sent,
                        b"",
                        is_rst=True,
                    )
            except Exception:
                pass

        await self.close(reason=reason, send_fin=False)

    async def close(self, reason="Unknown", send_fin=True):
        if self.closed:
            return

        self.closed = True
        self.close_reason = reason
        self._close_time = time.monotonic()

        if (
            send_fin
            and not self._fin_sent
            and not self._rst_sent
            and not self._rst_received
        ):
            self._fin_sent = True
            if self._fin_seq_sent is None:
                self._fin_seq_sent = self.snd_nxt
            try:
                if self.enable_control_reliability:
                    await self.send_control_packet(
                        packet_type=Packet_Type.STREAM_FIN,
                        sequence_num=self._fin_seq_sent,
                        payload=b"",
                        priority=4,
                        track_for_ack=True,
                        ack_type=Packet_Type.STREAM_FIN_ACK,
                    )
                else:
                    await self.enqueue_tx(
                        4,
                        self.stream_id,
                        self._fin_seq_sent,
                        b"",
                        is_fin=True,
                    )
            except Exception:
                pass

        current_task = asyncio.current_task()

        for task in (getattr(self, "io_task", None), getattr(self, "rtx_task", None)):
            if task and not task.done() and task is not current_task:
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=0.2)
                except Exception:
                    pass

        try:
            if (
                self.writer
                and hasattr(self.writer, "is_closing")
                and not self.writer.is_closing()
            ):
                self.writer.close()
                try:
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=0.5)
                except Exception:
                    pass
        except Exception:
            pass
