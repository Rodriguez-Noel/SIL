package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type client struct {
	conn net.Conn
	w    *bufio.Writer
	uid  uint32
}

type state struct {
	mu sync.Mutex

	instance     string
	visibility   string
	ownerUID     uint32
	socketPath   string
	metaPath     string
	registryPath string
	psPath       string
	cgmDir       string
	archiveDir   string
	appLogDir    string

	clients map[*client]struct{}

	psTimerOn bool
	psSeconds int

	ttlMinutes       int
	ttlUntil         time.Time
	ttlPaused        bool
	ttlRemainSeconds int64

	heartbeatOn      bool
	heartbeatSeconds int
	heartbeatTopN    int
	heartbeatLast    time.Time
	heartbeatSummary string

	listener net.Listener
}

func newServer(visibility string, ownerUID uint32, name string) (*state, error) {
	instance := buildInstanceID(visibility, ownerUID, name)
	socketPath, metaPath, registryPath, psPath, cgmDir, archiveDir, appLogDir, err := ensureDirs(instance)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	s := &state{
		instance:         instance,
		visibility:       visibility,
		ownerUID:         ownerUID,
		socketPath:       socketPath,
		metaPath:         metaPath,
		registryPath:     registryPath,
		psPath:           psPath,
		cgmDir:           cgmDir,
		archiveDir:       archiveDir,
		appLogDir:        appLogDir,
		clients:          make(map[*client]struct{}),
		psSeconds:        30,
		heartbeatSeconds: 3,
		heartbeatTopN:    5,
		listener:         l,
	}
	writeMeta(s, "running")
	_ = saveRegistry(s.registryPath, []monitorRecord{})
	return s, nil
}

func (s *state) logPath(name string) string { return filepath.Join(s.appLogDir, name) }

func (s *state) appendLog(name, msg string) {
	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339), msg)
	f, err := os.OpenFile(s.logPath(name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func (s *state) logOut(msg string) { s.appendLog("stdout.log", msg) }
func (s *state) logErr(msg string) { s.appendLog("stderr.log", msg) }
func (s *state) audit(msg string)  { s.appendLog("audit.log", msg) }

func (s *state) addClient(cl *client) {
	s.mu.Lock()
	s.clients[cl] = struct{}{}
	s.mu.Unlock()
}

func (s *state) delClient(cl *client) {
	s.mu.Lock()
	delete(s.clients, cl)
	s.mu.Unlock()
	_ = cl.conn.Close()
}

func runServer(s *state) {
	go s.psLoop()
	go s.ttlLoop()
	go s.heartbeatLoop()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		s.shutdown()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go handleClient(s, conn)
	}
}

func (s *state) notice(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for cl := range s.clients {
		send(cl.w, packet{Type: "notice", Msg: msg})
	}
}

func (s *state) ttlRemainingLocked() int64 {
	if s.ttlPaused {
		return s.ttlRemainSeconds
	}
	if s.ttlMinutes <= 0 && s.ttlUntil.IsZero() {
		return 0
	}
	if s.ttlUntil.IsZero() {
		return 0
	}
	d := time.Until(s.ttlUntil)
	if d < 0 {
		return 0
	}
	return int64(d.Round(time.Second) / time.Second)
}

func (s *state) statusData() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	psTimer := "off"
	if s.psTimerOn {
		psTimer = "on"
	}

	ttlState := "off"
	if s.ttlMinutes > 0 || !s.ttlUntil.IsZero() {
		ttlState = "on"
	}
	if s.ttlPaused {
		ttlState = "paused"
	}

	hbState := "off"
	if s.heartbeatOn {
		hbState = "on"
	}

	return map[string]any{
		"instance":              s.instance,
		"visibility":            s.visibility,
		"owner_uid":             s.ownerUID,
		"clients":               len(s.clients),
		"ps_timer":              psTimer,
		"ps_seconds":            s.psSeconds,
		"ttl_state":             ttlState,
		"ttl_remaining_seconds": s.ttlRemainingLocked(),
		"heartbeat_state":       hbState,
		"heartbeat_seconds":     s.heartbeatSeconds,
		"heartbeat_top_n":       s.heartbeatTopN,
		"heartbeat_summary":     s.heartbeatSummary,
	}
}

func (s *state) setTTL(minutes int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ttlMinutes = minutes
	s.ttlPaused = false
	if minutes <= 0 {
		s.ttlUntil = time.Time{}
		s.ttlRemainSeconds = 0
	} else {
		s.ttlRemainSeconds = int64((time.Duration(minutes) * time.Minute) / time.Second)
		s.ttlUntil = time.Now().Add(time.Duration(s.ttlRemainSeconds) * time.Second)
	}
	writeMeta(s, "running")
}

func (s *state) toggleTTL() (string, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ttlMinutes <= 0 && s.ttlUntil.IsZero() && s.ttlRemainSeconds <= 0 {
		return "off", 0
	}

	if s.ttlPaused || s.ttlUntil.IsZero() {
		remain := s.ttlRemainSeconds
		if remain <= 0 {
			return "off", 0
		}
		s.ttlPaused = false
		s.ttlUntil = time.Now().Add(time.Duration(remain) * time.Second)
		writeMeta(s, "running")
		return "on", remain
	}

	remain := s.ttlRemainingLocked()
	if remain <= 0 {
		s.ttlPaused = false
		s.ttlUntil = time.Time{}
		s.ttlRemainSeconds = 0
		writeMeta(s, "running")
		return "off", 0
	}

	s.ttlRemainSeconds = remain
	s.ttlPaused = true
	s.ttlUntil = time.Time{}
	writeMeta(s, "running")
	return "paused", remain
}

func (s *state) shutdown() {
	writeMeta(s, "stopped")
	s.audit("server shutdown")
	s.notice("server shutting down")

	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.socketPath)
	os.Exit(0)
}

func (s *state) psLoop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	var last time.Time
	for range t.C {
		s.mu.Lock()
		on := s.psTimerOn
		sec := s.psSeconds
		s.mu.Unlock()

		if !on {
			last = time.Time{}
			continue
		}

		if last.IsZero() || time.Since(last) >= time.Duration(sec)*time.Second {
			last = time.Now()
			rows, err := runPS(s.psPath)
			if err != nil {
				s.logErr("ps run failed: " + err.Error())
				s.notice("ps run failed")
			} else {
				s.logOut(fmt.Sprintf("ps updated rows=%d", len(rows)))
				s.notice(fmt.Sprintf("ps updated rows=%d", len(rows)))
			}
		}
	}
}

func (s *state) ttlLoop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for range t.C {
		s.mu.Lock()
		until := s.ttlUntil
		paused := s.ttlPaused
		s.mu.Unlock()

		if paused || until.IsZero() {
			continue
		}
		if time.Now().After(until) {
			s.shutdown()
			return
		}
	}
}

type hbTalker struct {
	Comm    string
	TGID    string
	Bytes   int64
	Archive string
}

func (s *state) heartbeatLoop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for range t.C {
		s.mu.Lock()
		on := s.heartbeatOn
		sec := s.heartbeatSeconds
		last := s.heartbeatLast
		topN := s.heartbeatTopN
		s.mu.Unlock()

		if !on {
			continue
		}
		if !last.IsZero() && time.Since(last) < time.Duration(sec)*time.Second {
			continue
		}

		s.mu.Lock()
		s.heartbeatLast = time.Now()
		writeMeta(s, "running")
		s.mu.Unlock()

		if err := s.heartbeatCycle(topN); err != nil {
			s.logErr("heartbeat failed: " + err.Error())
			s.notice("HEARTBEAT failed")
		}
	}
}

func (s *state) heartbeatCycle(topN int) error {
	rows, err := runPS(s.psPath)
	if err != nil {
		return err
	}

	allTgids := make([]string, 0, len(rows))
	commByTGID := make(map[string]string)
	ownerStr := fmt.Sprintf("%d", s.ownerUID)

	// Only sweep owner-owned user processes.
	for _, r := range rows {
		if r.UID != ownerStr {
			continue
		}
		if strings.TrimSpace(r.TGID) == "" || strings.TrimSpace(r.Comm) == "" {
			continue
		}
		allTgids = append(allTgids, r.TGID)
		if _, ok := commByTGID[r.TGID]; !ok {
			commByTGID[r.TGID] = r.Comm
		}
	}

	allTgids = dedupe(allTgids)
	if len(allTgids) == 0 {
		return nil
	}

	ts := time.Now().UTC().Format("20060102T150405")
	leanName := "hb_all_" + ts

	res, err := runHeartbeatCycleCGM(s.instance, leanName, "lean", allTgids, s.cgmDir, filepath.Join(s.archiveDir, "heartbeat"), s.logOut, s.logErr)
	if err != nil {
		return err
	}

	leanRows, err := parseLeanTSV(res.OutputPath)
	if err != nil {
		return err
	}

	sort.Slice(leanRows, func(i, j int) bool {
		return totalBytes(leanRows[i]) > totalBytes(leanRows[j])
	})

	if topN > len(leanRows) {
		topN = len(leanRows)
	}

	talkers := make([]hbTalker, 0, topN)
	for i := 0; i < topN; i++ {
		lr := leanRows[i]
		base := strings.ToLower(strings.TrimSpace(commByTGID[lr.TGID]))
		if base == "" {
			base = "unknown"
		}
		base = strings.ReplaceAll(base, " ", "_")
		logical := fmt.Sprintf("hb_%s_%s_%s", base, lr.TGID, ts)
		detail, derr := runHeartbeatCycleCGM(s.instance, logical, "default", []string{lr.TGID}, s.cgmDir, filepath.Join(s.archiveDir, "heartbeat"), s.logOut, s.logErr)
		arch := ""
		if derr == nil && detail != nil {
			arch = detail.ArchivePath
		}
		talkers = append(talkers, hbTalker{
			Comm:    commByTGID[lr.TGID],
			TGID:    lr.TGID,
			Bytes:   totalBytes(lr),
			Archive: arch,
		})
	}

	parts := make([]string, 0, len(talkers))
	for i, tkr := range talkers {
		parts = append(parts, fmt.Sprintf("%d.%s[%s]=%dB", i+1, tkr.Comm, tkr.TGID, tkr.Bytes))
	}

	summary := "HEARTBEAT: no active talkers"
	if len(parts) > 0 {
		summary = "HEARTBEAT: " + strings.Join(parts, " ")
	}
	s.mu.Lock()
	s.heartbeatSummary = summary
	s.mu.Unlock()

	s.audit(summary)
	s.notice(summary)
	return nil
}
