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
//	_ = m.Add("primary", "vpn.example.com:443", 10*time.Second)
//	tn, _ := m.Get("primary")
//	if err := tn.Connect(); err != nil {
//		log.Fatal(err)
//	}
//	defer tn.Close()
package tunnel
