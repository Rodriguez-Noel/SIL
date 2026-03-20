package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const dpBinPath = "./staging/bin/orc/dp/SIL_DP_O"

const landingBanner = `
  ░██████   ░██████░██
 ░██   ░██    ░██  ░██
░██           ░██  ░██
 ░████████    ░██  ░██         ░██
        ░██   ░██  ░██
 ░██   ░██    ░██  ░██
  ░██████   ░██████░██████████ ░██

  ░██████                            ░██████   ░██
 ░██   ░██                             ░██     ░██
░██          ░██████   ░██    ░██      ░██  ░████████
 ░████████        ░██  ░██    ░██      ░██     ░██
        ░██  ░███████  ░██    ░██      ░██     ░██
 ░██   ░██  ░██   ░██  ░██   ░███      ░██     ░██
  ░██████    ░█████░██  ░█████░██    ░██████    ░████
                              ░██
                        ░███████

░██                                      ░██
░██                                      ░██
░██          ░███████  ░██    ░██  ░████████  ░███████  ░██░████
░██         ░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██ ░███
░██         ░██    ░██ ░██    ░██ ░██    ░██ ░█████████ ░██
░██         ░██    ░██ ░██   ░███ ░██   ░███ ░██        ░██
░██████████  ░███████   ░█████░██  ░█████░██  ░███████  ░██
`

const smallBanner = `
┏━┓╻╻      ┏━┓┏━┓╻ ╻   ╻╺┳╸   ╻  ┏━┓╻ ╻╺┳┓┏━╸┏━┓
┗━┓┃┃  ╹   ┗━┓┣━┫┗┳┛   ┃ ┃    ┃  ┃ ┃┃ ┃ ┃┃┣╸ ┣┳┛
┗━┛╹┗━╸╹   ┗━┛╹ ╹ ╹    ╹ ╹    ┗━╸┗━┛┗━┛╺┻┛┗━╸╹┗╸
`

type packet struct {
	Type string         `json:"type"`
	OK   *bool          `json:"ok,omitempty"`
	Msg  string         `json:"msg,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

type cgmStatusRow struct {
	TGID       string
	BytesIn    string
	BytesOut   string
	PacketsIn  string
	PacketsOut string
	SrcPort    string
	DstPort    string
	IPV        string
	Protocol   string
	SAddr      string
	DAddr      string
}

var (
	firstPaint     = true
	lastStatusLine = ""
)

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

func connectOrLaunch(publicName string, privateName string, privateDefault bool, noSpawn bool) (net.Conn, string, error) {
	instanceID := buildInstanceID(publicName, privateName, privateDefault, os.Getuid())

	conn, err := dial(instanceID)
	if err != nil && !noSpawn {
		if err := startDetached(publicName, privateName, privateDefault); err != nil {
			return nil, "", err
		}
		if err := waitForSocket(instanceID, 5*time.Second); err != nil {
			return nil, "", err
		}
		conn, err = dial(instanceID)
	}

	return conn, instanceID, err
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func printHorizontalMenu() {
	fmt.Println("[S] [Q] [KILL] [Q!]")
	fmt.Println("[PS] [PS <N>] [PS FIND <Q>] [PS APPS] [PS T ON/OFF/<S>]")
	fmt.Println("[TTL] [TTL <MINUTES>]")
	fmt.Println("[CGM <APP>] [CGM DEFAULT|LEAN|GREEDY <APP>] [CGM STRICT ...]")
	fmt.Println("[CGM LS ...] [CGM LT ...] [CGM STATUS [NAME]] [CGM STOP <NAME>] [CGM STOP ALL]")
	fmt.Println("[CGM LT STOP <TGID> ...] [HEARTBEAT STATUS] [HEARTBEAT ON/OFF/<SECONDS>/TOP <N>] [HELP]")
}

func printBox(title string, lines []string) {
	maxw := len(title)
	for _, ln := range lines {
		if len(ln) > maxw {
			maxw = len(ln)
		}
	}
	border := "+" + strings.Repeat("-", maxw+2) + "+"
	fmt.Println(border)
	fmt.Printf("| %s%s |\n", title, strings.Repeat(" ", maxw-len(title)))
	fmt.Println(border)
	for _, ln := range lines {
		fmt.Printf("| %s%s |\n", ln, strings.Repeat(" ", maxw-len(ln)))
	}
	fmt.Println(border)
}

func printLandingPage() {
	clearScreen()
	fmt.Println(landingBanner)
	printHorizontalMenu()
	fmt.Println()
}

func printCompactFrame() {
	clearScreen()
	fmt.Println(smallBanner)
	printHorizontalMenu()
	if lastStatusLine != "" {
		fmt.Println()
		fmt.Println(lastStatusLine)
	}
	fmt.Println()
}

func beginRedraw() {
	if firstPaint {
		firstPaint = false
		return
	}
	printCompactFrame()
}

func printHelp() {
	clearScreen()
	fmt.Println(smallBanner)
	fmt.Println()

	printBox("GENERAL", []string{
		"S",
		"Q",
		"KILL",
		"Q!",
		"HELP",
	})

	printBox("PROCESS SNAPSHOT", []string{
		"PS",
		"PS <N>",
		"PS FIND <QUERY>",
		"PS APPS",
		"PS T ON",
		"PS T OFF",
		"PS T <SECONDS>",
	})

	printBox("TTL", []string{
		"TTL",
		"TTL <MINUTES>",
	})

	printBox("CGM", []string{
		"CGM <APP>",
		"CGM DEFAULT <APP>",
		"CGM LEAN <APP>",
		"CGM GREEDY <APP>",
		"CGM STRICT [DEFAULT|LEAN|GREEDY] <APP>",
		"CGM LS [DEFAULT|LEAN|GREEDY] <APP> [APP...]",
		"CGM LT [DEFAULT|LEAN|GREEDY] <TGID> [TGID...]",
		"CGM STATUS [NAME]",
		"CGM STOP <NAME>",
		"CGM STOP ALL",
		"CGM LT STOP <TGID> [TGID...]",
	})

	printBox("HEARTBEAT", []string{
		"HEARTBEAT STATUS",
		"HEARTBEAT ON",
		"HEARTBEAT OFF",
		"HEARTBEAT <SECONDS>",
		"HEARTBEAT TOP <N>",
	})

	fmt.Println()
}

func normalizeCommand(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	f := strings.Fields(raw)
	if len(f) == 0 {
		return ""
	}

	switch strings.ToUpper(f[0]) {
	case "HELP":
		return "__HELP__"
	case "S", "STATUS":
		return "status"
	case "Q", "QUIT":
		return "__QUIT__"
	case "KILL":
		return "kill"
	case "Q!":
		return "__KILL_AND_QUIT__"
	case "PS":
		if len(f) == 1 {
			return "ps"
		}
		if len(f) == 2 {
			return "ps " + f[1]
		}
		if len(f) >= 3 && strings.EqualFold(f[1], "find") {
			return "ps find " + strings.Join(f[2:], " ")
		}
		if len(f) == 3 && strings.EqualFold(f[1], "t") {
			return "ps t " + f[2]
		}
		return strings.ToLower(raw)
	case "TTL":
		if len(f) == 1 {
			return "ttl"
		}
		if len(f) == 2 {
			return "ttl " + f[1]
		}
		return strings.ToLower(raw)
	case "CGM":
		return strings.ToLower(raw)
	case "HEARTBEAT":
		return strings.ToLower(raw)
	}

	return strings.ToLower(raw)
}

func asString(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func rowFromPacket(m map[string]any) cgmStatusRow {
	return cgmStatusRow{
		TGID:       asString(m, "tgid"),
		BytesIn:    asString(m, "bytes_in"),
		BytesOut:   asString(m, "bytes_out"),
		PacketsIn:  asString(m, "packets_in"),
		PacketsOut: asString(m, "packets_out"),
		SrcPort:    asString(m, "src_port"),
		DstPort:    asString(m, "dst_port"),
		IPV:        asString(m, "ipv"),
		Protocol:   asString(m, "protocol"),
		SAddr:      asString(m, "saddr"),
		DAddr:      asString(m, "daddr"),
	}
}

func pad(s string, w int) string {
	if len(s) >= w {
		return s[:w]
	}
	return s + strings.Repeat(" ", w-len(s))
}

func printBoxRows(title string, rows []cgmStatusRow, perBox int) {
	if len(rows) == 0 {
		fmt.Printf("%s: no data rows found\n", title)
		return
	}

	for i := 0; i < len(rows); i += perBox {
		end := i + perBox
		if end > len(rows) {
			end = len(rows)
		}
		chunk := rows[i:end]

		colw := 14
		labelw := 17
		totalw := labelw + (len(chunk) * (colw + 3)) + 1
		fmt.Println(strings.Repeat("+", totalw))
		fmt.Printf("| %-15s", "TGID:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.TGID, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "Bytes in:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.BytesIn, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "Bytes out:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.BytesOut, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "Packets in:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.PacketsIn, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "Packets out:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.PacketsOut, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "Source Port:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.SrcPort, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "Dest Port:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.DstPort, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "IP Version:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.IPV, colw-1))
		}
		fmt.Println("|")
		fmt.Printf("| %-15s", "Protocol:")
		for _, r := range chunk {
			fmt.Printf("| %-13s ", pad(r.Protocol, colw-1))
		}
		fmt.Println("|")

		hasAddr := false
		for _, r := range chunk {
			if r.SAddr != "" || r.DAddr != "" {
				hasAddr = true
				break
			}
		}
		if hasAddr {
			fmt.Printf("| %-15s", "Source Addr:")
			for _, r := range chunk {
				v := r.SAddr
				if v == "" {
					v = "N/A"
				}
				fmt.Printf("| %-13s ", pad(v, colw-1))
			}
			fmt.Println("|")
			fmt.Printf("| %-15s", "Dest Addr:")
			for _, r := range chunk {
				v := r.DAddr
				if v == "" {
					v = "N/A"
				}
				fmt.Printf("| %-13s ", pad(v, colw-1))
			}
			fmt.Println("|")
		}
		fmt.Println(strings.Repeat("+", totalw))
	}
}

func renderPacket(p packet) {
	switch p.Type {
	case "hello":
		fmt.Printf("CONNECTED instance=%s visibility=%s owner=%s\n",
			asString(p.Data, "instance"),
			asString(p.Data, "visibility"),
			asString(p.Data, "owner_uid"))

	case "status":
		lastStatusLine = fmt.Sprintf(
			"STATUS instance=%s visibility=%s owner=%s clients=%s ps_timer=%s ps_seconds=%s ttl=%s ttl_remaining=%ss heartbeat=%s hb_seconds=%s hb_top=%s",
			asString(p.Data, "instance"),
			asString(p.Data, "visibility"),
			asString(p.Data, "owner_uid"),
			asString(p.Data, "clients"),
			asString(p.Data, "ps_timer"),
			asString(p.Data, "ps_seconds"),
			asString(p.Data, "ttl_state"),
			asString(p.Data, "ttl_remaining_seconds"),
			asString(p.Data, "heartbeat_state"),
			asString(p.Data, "heartbeat_seconds"),
			asString(p.Data, "heartbeat_top_n"),
		)

	case "ttl":
		fmt.Printf("TTL state=%s remaining=%ss\n",
			asString(p.Data, "ttl_state"),
			asString(p.Data, "ttl_remaining_seconds"))

	case "ack":
		fmt.Printf("OK %s\n", p.Msg)

	case "error":
		fmt.Printf("ERR %s\n", p.Msg)

	case "notice":
		fmt.Printf("NOTICE %s\n", p.Msg)

	case "ps_summary":
		fmt.Printf("PS rows_total=%s rows_shown=%s\n",
			asString(p.Data, "rows_total"),
			asString(p.Data, "rows_shown"))
		fmt.Println("PID\tTGID\tUID\tTHREADS\tCOMM")

	case "ps_row":
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n",
			asString(p.Data, "pid"),
			asString(p.Data, "tgid"),
			asString(p.Data, "uid"),
			asString(p.Data, "threads"),
			asString(p.Data, "comm"))

	case "ps_find":
		fmt.Printf("PS FIND query=%q rows_total=%s rows_shown=%s\n",
			asString(p.Data, "query"),
			asString(p.Data, "rows_total"),
			asString(p.Data, "rows_shown"))
		fmt.Println("PID\tTGID\tUID\tTHREADS\tCOMM")

	case "ps_apps":
		fmt.Printf("PS APPS count=%s\n", asString(p.Data, "count"))

	case "ps_app":
		fmt.Println(asString(p.Data, "name"))

	case "cgm_summary":
		fmt.Printf("CGM name=%s mode=%s count=%s tgids=%v archive=%s\n",
			asString(p.Data, "name"),
			asString(p.Data, "mode"),
			asString(p.Data, "count"),
			p.Data["tgids"],
			asString(p.Data, "archive"))

	case "cgm_registry":
		fmt.Printf("CGM STATUS active_monitors=%s\n", asString(p.Data, "count"))

	case "cgm_registry_item":
		fmt.Printf("- %s mode=%s active=%s count=%s archive=%s\n",
			asString(p.Data, "name"),
			asString(p.Data, "mode"),
			asString(p.Data, "active"),
			asString(p.Data, "count"),
			asString(p.Data, "archive"))

	case "cgm_status_meta":
		fmt.Printf("CGM STATUS %s mode=%s active=%s count=%s archive=%s\n",
			asString(p.Data, "name"),
			asString(p.Data, "mode"),
			asString(p.Data, "active"),
			asString(p.Data, "count"),
			asString(p.Data, "archive"))

	case "heartbeat_status":
		fmt.Printf("HEARTBEAT state=%s seconds=%s top=%s\n",
			asString(p.Data, "state"),
			asString(p.Data, "seconds"),
			asString(p.Data, "top_n"))
		if s := asString(p.Data, "summary"); s != "" {
			fmt.Println(s)
		}

	default:
		if p.Msg != "" {
			fmt.Println(p.Msg)
		}
	}
}

func renderResponse(pkts []packet) {
	beginRedraw()

	var cgmRows []cgmStatusRow
	for _, p := range pkts {
		if p.Type == "cgm_status_row" {
			cgmRows = append(cgmRows, rowFromPacket(p.Data))
			continue
		}
		renderPacket(p)
	}
	if len(cgmRows) > 0 {
		printBoxRows("CGM STATUS", cgmRows, 4)
	}
}

func readResponse(r *bufio.Reader) ([]packet, error) {
	out := []packet{}
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return out, err
		}
		var p packet
		if err := json.Unmarshal(line, &p); err != nil {
			continue
		}
		if p.Type == "end" {
			return out, nil
		}
		out = append(out, p)
	}
}

func main() {
	var publicName string
	var privateName string
	var privateDefault bool
	var noSpawn bool

	flag.StringVar(&publicName, "public", "", "connect to public instance")
	flag.StringVar(&privateName, "private", "", "connect to private named instance")
	flag.BoolVar(&privateDefault, "private-default", false, "connect to default private instance")
	flag.BoolVar(&noSpawn, "no-spawn", false, "do not auto-spawn server")
	flag.Parse()

	printLandingPage()

	conn, _, err := connectOrLaunch(publicName, privateName, privateDefault, noSpawn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	if pkts, err := readResponse(r); err == nil {
		renderResponse(pkts)
	}

	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !sc.Scan() {
			break
		}
		raw := strings.TrimSpace(sc.Text())
		cmd := normalizeCommand(raw)
		if cmd == "" {
			continue
		}
		if cmd == "__HELP__" {
			printHelp()
			continue
		}
		if cmd == "__QUIT__" {
			return
		}

		killAndQuit := false
		if cmd == "__KILL_AND_QUIT__" {
			cmd = "kill"
			killAndQuit = true
		}

		if _, err := w.WriteString(cmd + "\n"); err != nil {
			fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
			return
		}
		_ = w.Flush()

		pkts, err := readResponse(r)
		if err != nil {
			if cmd == "kill" {
				beginRedraw()
				fmt.Println("OK server stopped")
				if killAndQuit {
					return
				}
				fmt.Println("Client is still running. Use Q to exit.")
				continue
			}
			fmt.Fprintf(os.Stderr, "read failed: %v\n", err)
			return
		}
		renderResponse(pkts)

		if killAndQuit {
			return
		}
	}
}
