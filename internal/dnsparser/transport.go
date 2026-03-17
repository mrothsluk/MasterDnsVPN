// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"

	"masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/vpnproto"
)

var (
	ErrTXTAnswerMissing   = errors.New("dns txt answer missing")
	ErrTXTAnswerMalformed = errors.New("dns txt answer malformed")
	ErrTXTAnswerTooLarge  = errors.New("dns txt answer too large")
)

const (
	maxDNSNameLen       = 253
	maxDNSLabelLen      = 63
	maxTXTAnswerPayload = 255
	maxTXTEncodedChunk  = 160
)

func BuildTXTQuestionPacket(name string, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	qname, err := encodeDNSNameStrict(name)
	if err != nil {
		return nil, err
	}

	requestID, err := randomUint16()
	if err != nil {
		return nil, err
	}

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+len(qname)+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], enums.DNSQClassIN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], enums.DNSRecordTypeOPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet, nil
}

func BuildTXTResponsePacket(questionPacket []byte, answerName string, answerPayloads [][]byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount := extractQuestionSection(questionPacket, header)
	optRecords := extractOPTRecordsFromRequest(questionPacket, header, len(questionBytes) > 0 || header.QDCount == 0)

	nameBytes, err := encodeDNSNameStrict(answerName)
	if err != nil {
		return nil, err
	}

	answerLen := 0
	useAnswerNameCompression := len(answerPayloads) > 1
	for i, payload := range answerPayloads {
		nameLen := len(nameBytes)
		if useAnswerNameCompression && i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + len(payload)
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+rawRecordsLen(optRecords))
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, enums.DNSRCodeNoError))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answerPayloads)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(len(optRecords)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstAnswerNameOffset := offset

	for i, payload := range answerPayloads {
		if useAnswerNameCompression && i > 0 && firstAnswerNameOffset <= 0x3FFF {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|firstAnswerNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], enums.DNSRecordTypeTXT)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], enums.DNSQClassIN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(payload)))
		offset += 10
		offset += copy(response[offset:], payload)
	}

	for _, record := range optRecords {
		offset += copy(response[offset:], record)
	}

	return response, nil
}

func BuildVPNResponsePacket(questionPacket []byte, answerName string, packet vpnproto.Packet, baseEncode bool) ([]byte, error) {
	rawFrame, err := vpnproto.BuildRaw(vpnproto.BuildOptions{
		SessionID:       packet.SessionID,
		PacketType:      packet.PacketType,
		SessionCookie:   packet.SessionCookie,
		StreamID:        packet.StreamID,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  packet.TotalFragments,
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
	})
	if err != nil {
		return nil, err
	}

	answerPayloads, err := buildTXTAnswerChunks(rawFrame, baseEncode)
	if err != nil {
		return nil, err
	}
	return BuildTXTResponsePacket(questionPacket, answerName, answerPayloads)
}

func ExtractVPNResponse(packet []byte, baseEncoded bool) (vpnproto.Packet, error) {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return vpnproto.Packet{}, err
	}

	rawAnswers := extractTXTAnswerPayloads(parsed)
	if len(rawAnswers) == 0 {
		return vpnproto.Packet{}, ErrTXTAnswerMissing
	}

	return assembleVPNResponse(rawAnswers, baseEncoded)
}

func CalculateMaxEncodedQNameChars(domain string) int {
	domainLen := len(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domainLen <= 0 {
		return maxDNSNameLen
	}

	low := 0
	high := maxDNSNameLen
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if encodedQNameLen(mid, domainLen) <= maxDNSNameLen {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func EncodeDataToLabels(data string) string {
	if len(data) <= maxDNSLabelLen {
		return data
	}

	var b strings.Builder
	b.Grow(len(data) + len(data)/maxDNSLabelLen)
	for start := 0; start < len(data); start += maxDNSLabelLen {
		if start > 0 {
			b.WriteByte('.')
		}
		end := start + maxDNSLabelLen
		if end > len(data) {
			end = len(data)
		}
		b.WriteString(data[start:end])
	}
	return b.String()
}

func BuildTunnelQuestionName(domain string, encodedFrame string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", ErrInvalidName
	}
	if encodedFrame == "" {
		return domain, nil
	}

	name := EncodeDataToLabels(encodedFrame) + "." + domain
	if len(name) > maxDNSNameLen {
		return "", ErrInvalidName
	}
	return name, nil
}

func buildTXTAnswerChunks(rawFrame []byte, baseEncode bool) ([][]byte, error) {
	maxChunk := maxTXTAnswerPayload
	if baseEncode {
		maxChunk = maxTXTEncodedChunk
	}

	if len(rawFrame) == 0 {
		return [][]byte{appendLengthPrefixedTXT(nil)}, nil
	}

	encodeChunk := func(raw []byte) []byte {
		if !baseEncode {
			return appendLengthPrefixedTXT(raw)
		}
		encoded := basecodec.EncodeLowerBase36(raw)
		return appendLengthPrefixedTXT([]byte(encoded))
	}

	if len(rawFrame) <= maxChunk {
		return [][]byte{encodeChunk(rawFrame)}, nil
	}

	header, err := vpnproto.Parse(rawFrame)
	if err != nil {
		return [][]byte{encodeChunk(rawFrame)}, nil
	}

	headerLen := header.HeaderLength
	chunk0PrefixLen := 2
	maxChunk0Data := maxChunk - chunk0PrefixLen - headerLen
	if maxChunk0Data < 0 {
		maxChunk0Data = 0
	}

	remaining := len(header.Payload) - maxChunk0Data
	maxChunkNData := maxChunk - 1
	totalChunks := 1
	if remaining > 0 {
		totalChunks += (remaining + maxChunkNData - 1) / maxChunkNData
	}
	if totalChunks > 255 {
		return nil, ErrTXTAnswerTooLarge
	}

	chunks := make([][]byte, 0, totalChunks)
	rawChunk0 := make([]byte, 0, 2+len(rawFrame))
	rawChunk0 = append(rawChunk0, 0x00, byte(totalChunks))
	rawChunk0 = append(rawChunk0, rawFrame[:headerLen]...)
	rawChunk0 = append(rawChunk0, header.Payload[:min(maxChunk0Data, len(header.Payload))]...)
	chunks = append(chunks, encodeChunk(rawChunk0))

	cursor := maxChunk0Data
	for chunkID := 1; cursor < len(header.Payload); chunkID++ {
		end := cursor + maxChunkNData
		if end > len(header.Payload) {
			end = len(header.Payload)
		}
		rawChunk := make([]byte, 1+end-cursor)
		rawChunk[0] = byte(chunkID)
		copy(rawChunk[1:], header.Payload[cursor:end])
		chunks = append(chunks, encodeChunk(rawChunk))
		cursor = end
	}

	return chunks, nil
}

func appendLengthPrefixedTXT(data []byte) []byte {
	if len(data) <= 255 {
		out := make([]byte, 1+len(data))
		out[0] = byte(len(data))
		copy(out[1:], data)
		return out
	}

	parts := 1 + (len(data)-1)/255
	out := make([]byte, 0, len(data)+parts)
	for start := 0; start < len(data); start += 255 {
		end := start + 255
		if end > len(data) {
			end = len(data)
		}
		out = append(out, byte(end-start))
		out = append(out, data[start:end]...)
	}
	return out
}

func extractTXTAnswerPayloads(parsed Packet) [][]byte {
	if len(parsed.Answers) == 0 {
		return nil
	}

	payloads := make([][]byte, 0, len(parsed.Answers))
	for _, answer := range parsed.Answers {
		if answer.Type != enums.DNSRecordTypeTXT {
			continue
		}
		raw := extractTXTBytes(answer.RData)
		if len(raw) == 0 {
			continue
		}
		payloads = append(payloads, raw)
	}
	return payloads
}

func extractTXTBytes(rData []byte) []byte {
	if len(rData) == 0 {
		return nil
	}

	out := make([]byte, 0, len(rData))
	for offset := 0; offset < len(rData); {
		size := int(rData[offset])
		offset++
		if size == 0 {
			continue
		}
		if offset+size > len(rData) {
			out = append(out, rData[offset:]...)
			break
		}
		out = append(out, rData[offset:offset+size]...)
		offset += size
	}
	return out
}

func assembleVPNResponse(rawAnswers [][]byte, baseEncoded bool) (vpnproto.Packet, error) {
	if len(rawAnswers) == 1 {
		raw := rawAnswers[0]
		if baseEncoded {
			decoded, err := basecodec.DecodeLowerBase36(raw)
			if err != nil {
				return vpnproto.Packet{}, err
			}
			raw = decoded
		}
		return vpnproto.Parse(raw)
	}

	var chunks [256][]byte
	totalExpected := 0
	seenChunks := 0
	var header vpnproto.Packet
	headerSeen := false

	for _, raw := range rawAnswers {
		if baseEncoded {
			decoded, err := basecodec.DecodeLowerBase36(raw)
			if err != nil {
				return vpnproto.Packet{}, err
			}
			raw = decoded
		}
		if len(raw) == 0 {
			continue
		}

		if raw[0] == 0x00 {
			if len(raw) < 3 {
				return vpnproto.Packet{}, ErrTXTAnswerMalformed
			}
			totalExpected = int(raw[1])
			if totalExpected <= 0 || totalExpected > len(chunks) {
				return vpnproto.Packet{}, ErrTXTAnswerMalformed
			}
			parsed, err := vpnproto.ParseAtOffset(raw, 2)
			if err != nil {
				return vpnproto.Packet{}, err
			}
			header = parsed
			headerSeen = true
			if chunks[0] == nil {
				seenChunks++
			}
			chunks[0] = parsed.Payload
			continue
		}

		chunkID := int(raw[0])
		if chunkID >= len(chunks) {
			return vpnproto.Packet{}, ErrTXTAnswerMalformed
		}
		if chunks[chunkID] == nil {
			seenChunks++
		}
		chunks[chunkID] = raw[1:]
	}

	if !headerSeen || totalExpected <= 0 || seenChunks != totalExpected {
		return vpnproto.Packet{}, ErrTXTAnswerMalformed
	}
	for i := range totalExpected {
		if chunks[i] == nil {
			return vpnproto.Packet{}, ErrTXTAnswerMalformed
		}
	}
	for i := totalExpected; i < len(chunks); i++ {
		if chunks[i] != nil {
			return vpnproto.Packet{}, ErrTXTAnswerMalformed
		}
	}

	payloadLen := 0
	for i := range totalExpected {
		payloadLen += len(chunks[i])
	}

	payload := make([]byte, 0, payloadLen)
	for i := range totalExpected {
		payload = append(payload, chunks[i]...)
	}
	header.Payload = payload
	return header, nil
}

func encodeDNSNameStrict(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > maxDNSNameLen {
		return nil, ErrInvalidName
	}

	labels := strings.Split(name, ".")
	encoded := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if label == "" || len(label) > maxDNSLabelLen {
			return nil, ErrInvalidName
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	encoded = append(encoded, 0)
	return encoded, nil
}

func encodedQNameLen(encodedChars int, domainLen int) int {
	if encodedChars <= 0 {
		return domainLen
	}
	labelSplits := (encodedChars - 1) / maxDNSLabelLen
	return encodedChars + labelSplits + 1 + domainLen
}

func randomUint16() (uint16, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
