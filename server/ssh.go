package dprobe

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"golang.org/x/crypto/ssh"
)

var InstallFolder = "/etc/test-agent"

func ListenSSH(address string) error {
	authkeys := make(map[string]string)
	{
		keybytes, err := os.ReadFile(filepath.Join(InstallFolder, "authorized_keys"))
		if err != nil {
			return fmt.Errorf("reading authorized_keys file: %w", err)
		}

		for len(keybytes) > 0 {
			pubkey, who, _, rest, err := ssh.ParseAuthorizedKey(keybytes)
			if err != nil {
				return fmt.Errorf("parsing authorized_keys file: %w", err)
			}
			authkeys[string(pubkey.Marshal())] = who
			slog.Info("adding public key", "user", who)
			keybytes = rest
		}
	}

	config := &ssh.ServerConfig{
		ServerVersion: "SSH-DPROBE1",
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if w, ok := authkeys[string(key.Marshal())]; ok {
				return &ssh.Permissions{
					Extensions: map[string]string{"who": w},
				}, nil
			}
			return nil, fmt.Errorf("unknown key for user %s", conn.User())
		},
	}

	privateBytes, err := os.ReadFile(filepath.Join(InstallFolder, "id_ed25519"))
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}
	config.AddHostKey(private)

	// accepted.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", address, err)
	}

	// limit rate to 10 connections per seconds
	// this does not concern executions within the same connection
	bkt := ratelimit.NewBucket(1*time.Second, 10)

	for {
		bkt.Wait(1)
		tconn, err := listener.Accept()
		if err != nil {
			slog.Warn("failed to accept incoming connection", "error", err)
			continue
		}
		go serve(tconn, config)
	}
}

func serve(tconn net.Conn, config *ssh.ServerConfig) {
	defer tconn.Close()

	// upgrade TCP connection to SSH
	conn, chans, reqs, err := ssh.NewServerConn(tconn, config)
	if err != nil {
		slog.Warn("failed to handshake", "error", err)
		return
	}
	slog.Info("user login to test agent", "user", conn.Permissions.Extensions["who"])

	var wg sync.WaitGroup

	// RFC4254 §4
	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	// RFC4254 §5
	for nch := range chans {
		// rfc4250 §4.9.1
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		// RFC4254 §6
		session, requests, err := nch.Accept()
		if err != nil {
			slog.Info("Could not accept channel", "error", err)
		}

		// rfc4250 §4.9.3
		req := <-requests
		req.Reply(req.Type == "exec", nil)
		var cmd execMsg
		if err := ssh.Unmarshal(req.Payload, &cmd); err != nil {
			slog.Warn("cannot read exec payload", "error", err)
			session.Close()
			continue
		}

		if err := Run(cmd, session, requests); err != nil {
			slog.Info("failed to run command", "command", cmd, "error", err)
		}

		if err := session.Close(); err != nil && !errors.Is(err, io.EOF) {
			slog.Info("closing session", "error", err)
		}
	}
	wg.Wait()

}
