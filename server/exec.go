package agent

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// lightweight wrapper around
type execMsg struct {
	Command string
}

type Executor interface {
	Do(ssh.Channel, <-chan *ssh.Request, []string) error
}

var gmenu sync.Map

func init() {
	gmenu.Store("/coreutils/ls", bincmd("ls"))
}

func Run(cmd execMsg, ssn ssh.Channel, rq <-chan *ssh.Request) error {
	path, args := parseline(cmd.Command)
	rc, ok := gmenu.Load(path)
	if !ok {
		// rfc4254#section-6.10
		ssn.SendRequest("exit-status", false, ssh.Marshal(struct {
			Status uint32 `ssh:"exit_status"`
		}{uint32(1)}))
		ssn.CloseWrite()

		return fmt.Errorf("no such command %s", cmd.Command)
	}

	return rc.(Executor).Do(ssn, rq, args)
}

// bincmd is a locally installed executable
type bincmd string

func (c bincmd) Do(session ssh.Channel, requests <-chan *ssh.Request, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, string(c), args...)
	cmd.Stdin = session
	cmd.Stdout = session
	cmd.Stderr = session

	// handle remote signals
	go func() {
		for rq := range requests {
			if rq.Type != "signal" {
				slog.Debug("ignoring non-signal request", "type", rq.Type)
				continue
			}

			var sigm struct {
				Name string
			}
			if err := ssh.Unmarshal(rq.Payload, &sigm); err != nil {
				slog.Warn("invalid signal request", "error", err)
			}

			switch sigm.Name {
			case "INT", "KILL":
				slog.Debug("terminating", "cause", "remote-signal")
				cancel()
			default:
				slog.Debug("unexpected signal", "signal", sigm.Name)
			}
		}
	}()

	// int before kill
	cmd.Cancel = func() error { return softkill(cmd) }

	// return with exit code
	code := 0
	if err, ee := cmd.Run(), new(exec.ExitError); errors.As(err, &ee) {
		fmt.Println("ls error", err)
		code = ee.ExitCode()
	} else if err != nil {
		fmt.Println("no nil return??")
		return fmt.Errorf("running %v: %w", cmd, err)
	}

	// rfc4254#section-6.10
	session.SendRequest("exit-status", false, ssh.Marshal(struct {
		Status uint32 `ssh:"exit_status"`
	}{uint32(code)}))

	return session.CloseWrite()
}

func softkill(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(unix.SIGINT); err != nil {
		return fmt.Errorf("sending sigint: %w", err)
	}

	errc := make(chan error)

	go func() { errc <- cmd.Wait() }()

	select {
	case <-time.After(10 * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			return fmt.Errorf("sending sigkill: %w", err)
		}
	case err := <-errc:
		return err
	}

	if err := <-errc; err != nil {
		return err
	} else {
		return os.ErrProcessDone
	}
}

// parse parses a single line as a list of space-separated arguments.
// To embed a single quote, double it:
//
//	'Don''t communicate by sharing memory.'
//
// parseline reads a definition entry into a go structure using reflection
// match is performed on the spec tag, with numbers denotating positional arguments
// and names denotating named arguments.
func parseline(spec string) (cmd string, args []string) {
	if short := strings.TrimSpace(spec); short == "" || short[0] == '#' {
		return "", nil
	}

	for i, v := range splitWords(spec) {
		if i == 0 {
			cmd = v
		} else {
			args = append(args, v)
		}
	}
	return
}

// splitWords returns an iterator over all spaces-delimiteds words in a line
// leading and trimming spaces are not returned.
// spaces can be quoted using a single quote 'this contain space'
// single quotes can be double-quoted 'don”t share memory'
func splitWords(line string) iter.Seq2[int, string] {
	return func(yield func(int, string) bool) {
		lk := 0
		idx := 0

		peek := func() rune {
			if lk >= len(line) {
				return 0
			}
			rn, _ := utf8.DecodeRuneInString(line[lk:])
			return rn
		}

		next := func() rune {
			if lk >= len(line) {
				return 0
			}
			rn, sz := utf8.DecodeRuneInString(line[lk:])
			lk += sz
			return rn
		}
		splits := [utf8.RuneSelf]bool{' ': true, '\t': true, ',': true}
		space := func(r rune) bool { return r != 0 && r < utf8.RuneSelf && splits[r] }
		word := func(r rune) bool { return !space(r) && r != 0 }
		quote := func(r rune) bool { return r == '\'' }

		for peek() != 0 {
			for space(peek()) {
				next()
			}

			var st int
			if quote(peek()) {
				next()
				st = lk
				for !quote(peek()) {
					next()
				}
				// double quote '' -> '
				if quote(peek()) {
					// TODO
				}
			} else {
				st = lk
				for word(peek()) {
					next()
				}
			}

			if st < lk {
				if !yield(idx, line[st:lk]) {
					return
				}
				idx++
			}
		}
	}
}
