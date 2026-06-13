package masq

import (
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Server is a full HTTP/3 server that handles unauthenticated QUIC connections.
// It serves cached real-website content to fool active probes.
type Server struct {
	cache    *StaticCache
	http3srv *http3.Server
}

// NewServer creates a masquerade server backed by a StaticCache.
func NewServer(cache *StaticCache) *Server {
	s := &Server{cache: cache}
	s.http3srv = &http3.Server{
		Handler: cache.Handler(),
	}
	return s
}

// ServeQUICConn hands an existing QUIC connection to the HTTP/3 server.
// Called by core/server.go when authentication fails or times out.
func (s *Server) ServeQUICConn(conn *quic.Conn) error {
	return s.http3srv.ServeQUICConn(conn)
}
