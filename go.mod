module github.com/efrgdgr0024345/dnscheck

go 1.27.2

require (
	github.com/gorilla/websocket v1.5.3
	github.com/miekg/dns v1.1.73
	github.com/quic-go/quic-go v0.63.0
	github.com/valkey-io/valkey-go v1.0.78
	golang.org/x/text v0.42.0
	golang.org/x/time v0.16.0
)

require (
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/miekg/dns => github.com/brianshea2/go-dns v0.0.0-20261004185457-9ecbb7fa5212
