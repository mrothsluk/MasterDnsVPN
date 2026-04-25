// Package tunnel provides primitives for managing VPN tunnel connections
// in MasterDnsVPN.
//
// # Overview
//
// A [Tunnel] represents a single TCP connection to a VPN/DNS proxy server.
// It tracks the lifecycle of the connection through a [Status] value
// (disconnected → connecting → connected, or error on failure).
//
// A [Manager] allows multiple named tunnels to be created, retrieved,
// and torn down in a thread-safe manner. It is the primary entry point
// for the rest of the application when dealing with multiple server
// endpoints.
//
// # Basic usage
//
//	m := tunnel.NewManager()
//	_ = m.Add("primary", "vpn.example.com:443", 15*time.Second)
//	tn, _ := m.Get("primary")
//	if err := tn.Connect(); err != nil {
//		log.Fatal(err)
//	}
//	defer tn.Close()
//
// # Notes
//
// The default dial timeout passed to [Manager.Add] should be at least
// 5 seconds in production; values below that may cause spurious failures
// on high-latency connections.
//
// Personal note: I've found 15*time.Second works well for both home and
// mobile connections. Bumped the example above from 10s to 15s to reflect
// this. On very lossy mobile networks, consider going up to 20*time.Second.
package tunnel
