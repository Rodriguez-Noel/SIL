// orc/tui/SIL_TUI_UI.go
//
// Minimal standard-library TUI client for SIL dataplane instances.
// It uses ANSI clears/redraws and line input, no external dependencies.
//
// Default behavior:
// - connect to private-<uid>-default
// - if missing, spawn it
//
// Optional:
//   -public <name>
//   -private <name>
//   -private-default
//   -no-spawn

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const dpBinPath = "./staging/bin/orc/SIL_DP_O"

type uiState struct {
	mu      sync.Mutex
	lines   []string
	prompt  string
	title   string
	footer  string
}

func (u *uiState) addLine(line string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.lines = append(u.lines, line)
	if len(u.lines) > 25 {
		u.lines = u.lines[len(u.lines)-25:]
	}
}

func (u *uiState) render() {
	u.mu.Lock()
	defer u.mu.Unlock()

	fmt.Print("\033[2J\033[H")
	fmt.Println(u.title)
	fmt.Println(strings.Repeat("=", len(u.title)))
	fmt.Println()

	for _, line := range u.lines {
		fmt.Println(line)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("-", 72))
	fmt.Println("Commands: s | s! | q | cgm ... | ps | ps s:<query> | ps r on|off | ps t <sec> | ttl <minutes>")
	fmt.Println(u.footer)
	fmt.Print(u.prompt)
}

func repoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func buildInstanceID(publicName string, privateName string, privateDefault bool, uid int) string {
	if publicName != "" {
		return "public-" + publicName
	}
	if privateDefault {
		return fmt.Sprintf("private-%d-default", uid)
	}
	return fmt.Sprintf("private-%d-%s", uid, privateName)
}

func socketPath(instanceID string) string {
	return filepath.Join(repoRoot(), "data", "instances", instanceID, "server.sock")
}

func dial(instanceID string) (net.Conn, error) {
	return net.Dial("unix", socketPath(instanceID))
}

func startDetached(publicName string, privateName string, privateDefault bool) error {
	args := []string{}
	switch {
	case publicName != "":
		args = append(args, "--public", publicName)
	case privateDefault:
		args = append(args, "--private-default")
	default:
		args = append(args, "--private", privateName)
	}

	cmd := exec.Command(dpBinPath, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	cmd.Dir = repoRoot()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func waitForSocket(instanceID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath(instanceID)); err == nil {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("socket not ready")
}

func main() {
	var publicName string
	var privateName string
	var privateDefault bool
	var noSpawn bool

	flag.StringVar(&publicName, "public", "", "connect/start public instance")
	flag.StringVar(&privateName, "private", "", "connect/start named private instance")
	flag.BoolVar(&privateDefault, "private-default", false, "connect/start default private instance")
	flag.BoolVar(&noSpawn, "no-spawn", false, "do not spawn instance if missing")
	flag.Parse()

	modeCount := 0
	if publicName != "" {
		modeCount++
	}
	if privateName != "" {
		modeCount++
	}
	if privateDefault {
		modeCount++
	}
	if modeCount == 0 {
		privateDefault = true
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "choose only one of -public, -private, -private-default")
		os.Exit(2)
	}

	instanceID := buildInstanceID(publicName, privateName, privateDefault, os.Getuid())

	conn, err := dial(instanceID)
	if err != nil && !noSpawn {
		if err := startDetached(publicName, privateName, privateDefault); err != nil {
			fmt.Fprintf(os.Stderr, "SIL_TUI_UI: start failed: %v\n", err)
			os.Exit(1)
		}
		if err := waitForSocket(instanceID, 5*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "SIL_TUI_UI: wait socket failed: %v\n", err)
			os.Exit(1)
		}
		conn, err = dial(instanceID)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "SIL_TUI_UI: connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	ui := &uiState{
		title:  "SIL TUI — " + instanceID,
		prompt: "> ",
		footer: "Connected.",
	}
	ui.render()

	go func() {
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			ui.addLine(sc.Text())
			ui.render()
		}
		ui.footer = "Disconnected."
		ui.render()
		os.Exit(0)
	}()

	in := bufio.NewReader(os.Stdin)
	for {
		ui.render()
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}

		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}

		ui.addLine("CMD " + cmd)

		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			ui.addLine("ERR write failed: " + err.Error())
			ui.render()
			return
		}

		if cmd == "q" {
			return
		}
	}
}
