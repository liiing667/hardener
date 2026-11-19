// Package dashboard renders the audit/fix runner without owning hardening logic.
package dashboard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"hardener/internal/config"
	"hardener/internal/executor"
	"hardener/internal/ui"
)

type Options struct {
	Mode          string
	System        string
	SecurityLevel string
	KeepSudoAlive bool
}

// Work runs the executor with the dashboard's observer and stop signal. It
// returns the structured run status alongside any error so the renderer and
// the caller share the same coverage/stop evidence.
type Work func(observer executor.Observer, stop *executor.StopHandle) (executor.RunStatus, error)

// Stop reasons recorded on the report; they stay user-readable in the UI.
const (
	reasonUserStop          = "user requested stop at the next check boundary"
	reasonSudoRefreshFailed = "sudo credential refresh failed; stopping after the current check"
)

var ErrStopped = errors.New("run stopped by user; completed checks were retained")

func Available() bool {
	return os.Getenv("TERM") != "dumb" && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// Run owns the terminal until the user closes the completed dashboard. Quit
// during execution requests a boundary stop instead of killing an active fix.
func Run(options Options, suites []config.TestSuite, work Work) error {
	if !Available() {
		return errors.New("dashboard requires an interactive terminal")
	}
	ready, exited, workerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var stopHandle executor.StopHandle
	requestStop := func() { stopHandle.Request(reasonUserStop) }
	m := newModel(options, suites, ready, requestStop)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithFPS(20), tea.WithoutSignalHandler())

	restore := ui.SetLogSink(func(entry ui.LogEntry) {
		// Structured runner events already render these statuses accurately.
		switch entry.Level {
		case "pass", "fail", "skip", "suite", "summary":
			return
		}
		p.Send(entry)
	})
	defer restore()

	var workErr error
	var runStatus executor.RunStatus
	go func() {
		defer close(workerDone)
		select {
		case <-ready:
		case <-exited:
			return
		}
		// Bubble Tea can fail before startup. Do not start work after that.
		select {
		case <-exited:
			return
		default:
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					workErr = fmt.Errorf("execution panicked: %v", r)
				}
			}()
			runStatus, workErr = work(func(event executor.RunEvent) { p.Send(event) }, &stopHandle)
		}()
		p.Send(finishedMsg{err: workErr, status: runStatus, stopping: stopHandle.StopRequested()})
	}()

	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)
	go func() {
		for {
			select {
			case <-interrupts:
				p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
			case <-exited:
				return
			}
		}
	}()
	if options.KeepSudoAlive {
		go func() {
			ticker := time.NewTicker(40 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-workerDone:
					return
				case <-exited:
					return
				case <-ticker.C:
					// Never prompt for credentials while the terminal is in raw mode.
					if err := exec.Command("sudo", "-n", "-v").Run(); err != nil {
						stopHandle.Request(reasonSudoRefreshFailed)
						p.Send(ui.LogEntry{Level: "error", Message: "Sudo credential refresh failed; stopping after the current check."})
						return
					}
				}
			}
		}()
	}

	_, terminalErr := p.Run()
	close(exited)
	// Even a renderer error must not leave a background fix orphaned.
	wasStopped := stopHandle.StopRequested()
	requestStop()
	<-workerDone
	if terminalErr != nil {
		return terminalErr
	}
	if workErr != nil {
		return workErr
	}
	if wasStopped && runStatus.Incomplete {
		return ErrStopped
	}
	return nil
}
