package gost

import (
	"context"
	"net"
	"net/url"
	"time"
	
	"github.com/Microsoft/go-winio"
)

// smbnpTransporter is a SMB Named Pipe transporter.
type smbnpTransporter struct{}

// SMBNPTransporter creates a SMB Named Pipe client.
func SMBNPTransporter() Transporter {
	return &smbnpTransporter{}
}

func (tr *smbnpTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	// Construct the named pipe path
	// smbnp://host/pipeName -> \\host\pipe\pipeName
	pipePath := `\\` + u.Host + `\pipe\` + u.Path[1:] // Remove leading slash

	// Apply dial options
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	// Set timeout if specified
	timeout := 5 * time.Second
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	// Dial the named pipe with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	conn, err := winio.DialPipeContext(ctx, pipePath)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (tr *smbnpTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	// For SMBNP, handshake is not needed as the connection is already established
	// Just return the connection as-is
	return conn, nil
}

func (tr *smbnpTransporter) Multiplex() bool {
	// Named pipes don't support built-in multiplexing
	return false
}

// smbnpListener for server side
type smbnpListener struct {
	net.Listener
}

// SMBNPListener creates a Listener for SMB Named Pipe proxy server.
func SMBNPListener(addr string) (Listener, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	// Construct the named pipe path for server
	// smbnp://:pipeName -> \\.\pipe\pipeName
	pipePath := `\\.\pipe\` + u.Path[1:] // Remove leading slash

	// Create pipe configuration
	config := &winio.PipeConfig{}

	// Listen on the named pipe
	ln, err := winio.ListenPipe(pipePath, config)
	if err != nil {
		return nil, err
	}

	return &smbnpListener{Listener: ln}, nil
}
