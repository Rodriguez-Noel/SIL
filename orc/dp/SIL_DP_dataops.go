package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ARG_FAULT = 2
	SYS_FAULT = 3

	psOptBin     = "./staging/bin/opt/SIL_PS_opt"
	cgmOptBin    = "./staging/bin/opt/SIL_CGM_opt"
	globalCgmOut = "./data/cgm/cgm.tsv"
	globalCgmLck = "./data/tmp/cgm_opt.lock"
)

type packet struct {
	Type string         `json:"type"`
	OK   *bool          `json:"ok,omitempty"`
	Msg  string         `json:"msg,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

type psRow struct {
	PID  string
	TGID string
	UID  string
	Thr  string
	Comm string
}

type appGroup struct {
	Comm  string
	TGIDs []string
}

type monitorRecord struct {
	Name             string   `json:"name"`
	Internal         string   `json:"internal"`
	Mode             string   `json:"mode"`
	TGIDs            []string `json:"tgids"`
	OutputPath       string   `json:"output_path"`
	LastArchivePath  string   `json:"last_archive_path"`
	Active           bool     `json:"active"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
	HeartbeatManaged bool     `json:"heartbeat_managed"`
}

type cgmRunResult struct {
	OutputPath  string
	ArchivePath string
}

type leanRow struct {
	TGID       string
	InPackets  int64
	InBytes    int64
	OutPackets int64
	OutBytes   int64
}

type defaultARow struct {
	TGID       string
	IPV        string
	Protocol   string
	InPackets  int64
	InBytes    int64
	OutPackets int64
	OutBytes   int64
}

type defaultBRow struct {
	TGID       string
	Protocol   string
	SPort      string
	DPort      string
	InPackets  int64
	InBytes    int64
	OutPackets int64
	OutBytes   int64
}

type defaultStatusRow struct {
	TGID       string
	BytesIn    int64
	BytesOut   int64
	PacketsIn  int64
	PacketsOut int64
	SrcPort    string
	DstPort    string
	IPV        string
	Protocol   string
}

type greedyRow struct {
	TGID       string
	IPV        string
	Protocol   string
	SPort      string
	DPort      string
	SAddr      string
	DAddr      string
	InPackets  int64
	InBytes    int64
	OutPackets int64
	OutBytes   int64
}

type greedyStatusRow struct {
	TGID       string
	BytesIn    int64
	BytesOut   int64
	PacketsIn  int64
	PacketsOut int64
	SrcPort    string
	DstPort    string
	SAddr      string
	DAddr      string
	IPV        string
	Protocol   string
}

func okptr(v bool) *bool { return &v }

func repoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func buildInstanceID(vis string, uid uint32, name string) string {
	if vis == "public" {
		return "public-" + name
	}
	return fmt.Sprintf("private-%d-%s", uid, name)
}

func ensureDirs(instance string) (string, string, string, string, string, string, string, error) {
	root := repoRoot()
	data := filepath.Join(root, "data")

	socketPath := filepath.Join(data, "instances", instance, "server.sock")
	metaPath := filepath.Join(data, "instances", instance, "meta.json")
	registryPath := filepath.Join(data, "instances", instance, "cgm_registry.json")
	psPath := filepath.Join(data, "ps", instance, "snapshot.tsv")
	cgmDir := filepath.Join(data, "cgm", instance)
	archiveDir := filepath.Join(data, "archive", instance)
	appLogDir := filepath.Join(data, "logs", "app")

	dirs := []string{
		filepath.Dir(socketPath),
		filepath.Dir(psPath),
		cgmDir,
		archiveDir,
		filepath.Join(archiveDir, "cgm"),
		filepath.Join(archiveDir, "heartbeat"),
		appLogDir,
		filepath.Join(data, "tmp"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return "", "", "", "", "", "", "", err
		}
	}

	return socketPath, metaPath, registryPath, psPath, cgmDir, archiveDir, appLogDir, nil
}

func writeMeta(s *state, status string) {
	f, err := os.Create(s.metaPath)
	if err != nil {
		return
	}
	defer f.Close()

	_ = json.NewEncoder(f).Encode(map[string]any{
		"instance_id":        s.instance,
		"visibility":         s.visibility,
		"owner_uid":          s.ownerUID,
		"socket_path":        s.socketPath,
		"pid":                os.Getpid(),
		"created_at":         time.Now(),
		"ttl_minutes":        s.ttlMinutes,
		"status":             status,
		"heartbeat_on":       s.heartbeatOn,
		"heartbeat_interval": s.heartbeatSeconds,
		"heartbeat_top_n":    s.heartbeatTopN,
	})
}

func send(w *bufio.Writer, p packet) {
	_ = json.NewEncoder(w).Encode(p)
	_ = w.Flush()
}

func endPacket(w *bufio.Writer) { send(w, packet{Type: "end"}) }

func reply(w *bufio.Writer, typ string, ok bool, msg string, data map[string]any) {
	send(w, packet{Type: typ, OK: okptr(ok), Msg: msg, Data: data})
}

func peerUID(conn net.Conn) uint32 {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return 0
	}

	var uid uint32
	_ = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err == nil {
			uid = uint32(cred.Uid)
		}
	})
	return uid
}

func runPS(outPath string) ([]psRow, error) {
	cmd := exec.Command(psOptBin, outPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	cmd.Dir = repoRoot()

	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return readPS(outPath)
}

func withLock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	return fn()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func namespacedCGMName(instance, logical string) string {
	var b strings.Builder
	b.WriteString(logical)
	b.WriteString("__")
	for _, r := range instance {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func modeFlag(mode string) []string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "lean":
		return []string{"-l"}
	case "greedy":
		return []string{"-g"}
	default:
		return nil
	}
}

func archiveCGMRun(baseDir, kind, logical, mode string, tgids []string, srcPath string) (string, error) {
	ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	archivePath := filepath.Join(baseDir, kind, logical, ts)
	if err := os.MkdirAll(archivePath, 0755); err != nil {
		return "", err
	}

	rawPath := filepath.Join(archivePath, "raw.tsv")
	if err := copyFile(srcPath, rawPath); err != nil {
		return "", err
	}

	meta := map[string]any{
		"logical_name": logical,
		"mode":         mode,
		"tgids":        tgids,
		"collected_at": ts,
		"source_path":  srcPath,
		"raw_path":     rawPath,
	}
	mf, err := os.Create(filepath.Join(archivePath, "metadata.json"))
	if err == nil {
		_ = json.NewEncoder(mf).Encode(meta)
		_ = mf.Close()
	}

	return archivePath, nil
}

func stopPins(mode, internal string) {
	if mode == "" || internal == "" {
		return
	}
	_ = os.RemoveAll(filepath.Join("/sys/fs/bpf/sil/cgm", mode, internal))
}

func runCGMMode(instance, logical, mode string, tgids []string, cgmDir, archiveDir string, logOut, logErr func(string)) (*cgmRunResult, error) {
	internal := namespacedCGMName(instance, logical)
	dst := filepath.Join(cgmDir, logical+".tsv")
	var res cgmRunResult

	err := withLock(globalCgmLck, func() error {
		// Replace existing monitor state for the same logical name.
		stopPins(mode, internal)

		args := []string{}
		args = append(args, modeFlag(mode)...)
		args = append(args, internal)
		args = append(args, tgids...)

		cmd := exec.Command(cgmOptBin, args...)
		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb
		cmd.Stdin = nil
		cmd.Dir = repoRoot()

		err := cmd.Run()
		if s := strings.TrimSpace(outb.String()); s != "" && logOut != nil {
			logOut(fmt.Sprintf("cgm mode=%s logical=%s tgids=%v stdout=%s", mode, logical, tgids, s))
		}
		if s := strings.TrimSpace(errb.String()); s != "" && logErr != nil {
			logErr(fmt.Sprintf("cgm mode=%s logical=%s tgids=%v stderr=%s", mode, logical, tgids, s))
		}
		if err != nil {
			return err
		}

		if err := copyFile(globalCgmOut, dst); err != nil {
			return err
		}

		arch, err := archiveCGMRun(archiveDir, "cgm", logical, mode, tgids, dst)
		if err != nil {
			return err
		}

		res.OutputPath = dst
		res.ArchivePath = arch
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func refreshCGMMode(instance string, rec monitorRecord, archiveDir string, logOut, logErr func(string)) (*cgmRunResult, error) {
	dst := rec.OutputPath
	var res cgmRunResult

	err := withLock(globalCgmLck, func() error {
		args := []string{"-r"}
		args = append(args, modeFlag(rec.Mode)...)
		args = append(args, rec.Internal)

		cmd := exec.Command(cgmOptBin, args...)
		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb
		cmd.Stdin = nil
		cmd.Dir = repoRoot()

		err := cmd.Run()
		if s := strings.TrimSpace(outb.String()); s != "" && logOut != nil {
			logOut(fmt.Sprintf("cgm refresh mode=%s logical=%s tgids=%v stdout=%s", rec.Mode, rec.Name, rec.TGIDs, s))
		}
		if s := strings.TrimSpace(errb.String()); s != "" && logErr != nil {
			logErr(fmt.Sprintf("cgm refresh mode=%s logical=%s tgids=%v stderr=%s", rec.Mode, rec.Name, rec.TGIDs, s))
		}
		if err != nil {
			return err
		}

		if err := copyFile(globalCgmOut, dst); err != nil {
			return err
		}

		arch, err := archiveCGMRun(archiveDir, "cgm", rec.Name, rec.Mode, rec.TGIDs, dst)
		if err != nil {
			return err
		}

		res.OutputPath = dst
		res.ArchivePath = arch
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func runHeartbeatCycleCGM(instance, logical, mode string, tgids []string, cgmDir, archiveDir string, logOut, logErr func(string)) (*cgmRunResult, error) {
	res, err := runCGMMode(instance, logical, mode, tgids, cgmDir, archiveDir, logOut, logErr)
	if err != nil {
		return nil, err
	}

	rec := monitorRecord{
		Name:            logical,
		Internal:        namespacedCGMName(instance, logical),
		Mode:            mode,
		TGIDs:           tgids,
		OutputPath:      res.OutputPath,
		LastArchivePath: res.ArchivePath,
		Active:          true,
	}

	time.Sleep(2 * time.Second)

	refreshed, err := refreshCGMMode(instance, rec, archiveDir, logOut, logErr)
	if err == nil && refreshed != nil {
		res = refreshed
	}

	stopPins(mode, namespacedCGMName(instance, logical))
	return res, nil
}

func readPS(path string) ([]psRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rows := make([]psRow, 0, 256)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		// Skip TSV header row from the PS utility.
		if parts[0] == "PID" && parts[1] == "TGID" {
			continue
		}
		rows = append(rows, psRow{
			PID:  parts[0],
			TGID: parts[1],
			UID:  parts[2],
			Thr:  parts[3],
			Comm: parts[4],
		})
	}
	return rows, sc.Err()
}

func groupApps(rows []psRow) []appGroup {
	m := make(map[string]*appGroup)

	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.Comm))
		if key == "" {
			continue
		}

		g, ok := m[key]
		if !ok {
			g = &appGroup{Comm: row.Comm}
			m[key] = g
		}

		found := false
		for _, t := range g.TGIDs {
			if t == row.TGID {
				found = true
				break
			}
		}
		if !found {
			g.TGIDs = append(g.TGIDs, row.TGID)
		}
	}

	out := make([]appGroup, 0, len(m))
	for _, g := range m {
		sort.Strings(g.TGIDs)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Comm) < strings.ToLower(out[j].Comm)
	})
	return out
}

func psFind(rows []psRow, q string, limit int) ([]psRow, int) {
	needle := strings.ToLower(strings.TrimSpace(q))
	if needle == "" {
		return nil, 0
	}

	out := make([]psRow, 0)
	total := 0
	for _, row := range rows {
		if strings.HasPrefix(strings.ToLower(row.Comm), needle) {
			total++
			if len(out) < limit {
				out = append(out, row)
			}
		}
	}
	return out, total
}

func appExact(groups []appGroup, name string) *appGroup {
	needle := strings.ToLower(strings.TrimSpace(name))
	for _, g := range groups {
		if strings.ToLower(g.Comm) == needle {
			cp := g
			return &cp
		}
	}
	return nil
}

func appPrefix(groups []appGroup, name string) []appGroup {
	needle := strings.ToLower(strings.TrimSpace(name))
	out := make([]appGroup, 0)
	for _, g := range groups {
		if strings.HasPrefix(strings.ToLower(g.Comm), needle) {
			out = append(out, g)
		}
	}
	return out
}

func dedupe(xs []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func loadRegistry(path string) ([]monitorRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []monitorRecord{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return []monitorRecord{}, nil
	}

	var out []monitorRecord
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func saveRegistry(path string, recs []monitorRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func upsertRegistryRecord(path string, rec monitorRecord) error {
	recs, err := loadRegistry(path)
	if err != nil {
		return err
	}

	updated := false
	for i := range recs {
		if recs[i].Name == rec.Name {
			recs[i] = rec
			updated = true
			break
		}
	}
	if !updated {
		recs = append(recs, rec)
	}

	sort.Slice(recs, func(i, j int) bool { return recs[i].Name < recs[j].Name })
	return saveRegistry(path, recs)
}

func markRegistryInactive(path string, names []string) error {
	recs, err := loadRegistry(path)
	if err != nil {
		return err
	}

	set := map[string]struct{}{}
	for _, n := range names {
		set[n] = struct{}{}
	}

	for i := range recs {
		if _, ok := set[recs[i].Name]; ok {
			recs[i].Active = false
			recs[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	return saveRegistry(path, recs)
}

func activeRegistry(path string) ([]monitorRecord, error) {
	recs, err := loadRegistry(path)
	if err != nil {
		return nil, err
	}

	out := make([]monitorRecord, 0, len(recs))
	for _, r := range recs {
		if r.Active {
			out = append(out, r)
		}
	}
	return out, nil
}

func findRegistryByName(path, name string) (*monitorRecord, error) {
	recs, err := loadRegistry(path)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if strings.EqualFold(r.Name, name) {
			cp := r
			return &cp, nil
		}
	}
	return nil, nil
}

func stopMonitor(instance, archiveDir, registryPath string, rec monitorRecord) error {
	stopPins(rec.Mode, rec.Internal)

	if rec.OutputPath != "" {
		_, _ = archiveCGMRun(archiveDir, "cgm", rec.Name+"_final", rec.Mode, rec.TGIDs, rec.OutputPath)
		_ = os.Remove(rec.OutputPath)
	}

	return markRegistryInactive(registryPath, []string{rec.Name})
}

func parseLeanTSV(path string) ([]leanRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := []leanRow{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 6 || parts[0] != "LEAN" {
			continue
		}

		vals := make([]int64, 4)
		for i := 0; i < 4; i++ {
			n, err := strconv.ParseInt(parts[i+2], 10, 64)
			if err != nil {
				n = 0
			}
			vals[i] = n
		}

		out = append(out, leanRow{
			TGID:       parts[1],
			InPackets:  vals[0],
			InBytes:    vals[1],
			OutPackets: vals[2],
			OutBytes:   vals[3],
		})
	}

	return out, sc.Err()
}

func parseDefaultTSV(path string) ([]defaultARow, []defaultBRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	aRows := []defaultARow{}
	bRows := []defaultBRow{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		switch parts[0] {
		case "DEFAULT_A":
			if len(parts) != 8 {
				continue
			}
			inPk, _ := strconv.ParseInt(parts[4], 10, 64)
			inBy, _ := strconv.ParseInt(parts[5], 10, 64)
			outPk, _ := strconv.ParseInt(parts[6], 10, 64)
			outBy, _ := strconv.ParseInt(parts[7], 10, 64)
			aRows = append(aRows, defaultARow{
				TGID:       parts[1],
				IPV:        parts[2],
				Protocol:   parts[3],
				InPackets:  inPk,
				InBytes:    inBy,
				OutPackets: outPk,
				OutBytes:   outBy,
			})
		case "DEFAULT_B":
			if len(parts) != 9 {
				continue
			}
			inPk, _ := strconv.ParseInt(parts[5], 10, 64)
			inBy, _ := strconv.ParseInt(parts[6], 10, 64)
			outPk, _ := strconv.ParseInt(parts[7], 10, 64)
			outBy, _ := strconv.ParseInt(parts[8], 10, 64)
			bRows = append(bRows, defaultBRow{
				TGID:       parts[1],
				Protocol:   parts[2],
				SPort:      parts[3],
				DPort:      parts[4],
				InPackets:  inPk,
				InBytes:    inBy,
				OutPackets: outPk,
				OutBytes:   outBy,
			})
		}
	}
	return aRows, bRows, sc.Err()
}


func formatIPv4FromUint32Text(s string) string {
	u, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return "N/A"
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func formatIPv6FromUint32Texts(parts []string) string {
	if len(parts) != 4 {
		return "N/A"
	}
	words := make([]uint32, 4)
	for i, p := range parts {
		u, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return "N/A"
		}
		words[i] = uint32(u)
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		(words[0]>>16)&0xffff, words[0]&0xffff,
		(words[1]>>16)&0xffff, words[1]&0xffff,
		(words[2]>>16)&0xffff, words[2]&0xffff,
		(words[3]>>16)&0xffff, words[3]&0xffff)
}

func formatGreedyIP(ipv string, parts []string) string {
	switch strings.TrimSpace(ipv) {
	case "2", "4":
		if len(parts) >= 1 {
			return formatIPv4FromUint32Text(parts[0])
		}
	case "10", "6":
		return formatIPv6FromUint32Texts(parts)
	}
	if len(parts) >= 1 {
		return formatIPv4FromUint32Text(parts[0])
	}
	return "N/A"
}

func parseGreedyTSV(path string) ([]greedyRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := []greedyRow{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "	")
		if len(parts) != 18 || parts[0] != "GREEDY" {
			continue
		}

		inPk, _ := strconv.ParseInt(parts[14], 10, 64)
		inBy, _ := strconv.ParseInt(parts[15], 10, 64)
		outPk, _ := strconv.ParseInt(parts[16], 10, 64)
		outBy, _ := strconv.ParseInt(parts[17], 10, 64)

		sAddr := formatGreedyIP(parts[2], parts[6:10])
		dAddr := formatGreedyIP(parts[2], parts[10:14])

		out = append(out, greedyRow{
			TGID:       parts[1],
			IPV:        parts[2],
			Protocol:   parts[3],
			SPort:      parts[4],
			DPort:      parts[5],
			SAddr:      sAddr,
			DAddr:      dAddr,
			InPackets:  inPk,
			InBytes:    inBy,
			OutPackets: outPk,
			OutBytes:   outBy,
		})
	}

	return out, sc.Err()
}

func totalBytes(r leanRow) int64 { return r.InBytes + r.OutBytes }

func summarizeDefaultStatus(path string) ([]defaultStatusRow, error) {
	aRows, bRows, err := parseDefaultTSV(path)
	if err != nil {
		return nil, err
	}

	type acc struct {
		defaultStatusRow
		portBytes int64
	}
	m := map[string]*acc{}

	for _, r := range aRows {
		x, ok := m[r.TGID]
		if !ok {
			x = &acc{defaultStatusRow: defaultStatusRow{
				TGID:     r.TGID,
				SrcPort:  "N/A",
				DstPort:  "N/A",
				IPV:      r.IPV,
				Protocol: r.Protocol,
			}}
			m[r.TGID] = x
		}
		x.BytesIn += r.InBytes
		x.BytesOut += r.OutBytes
		x.PacketsIn += r.InPackets
		x.PacketsOut += r.OutPackets
		if x.IPV == "" || x.IPV == "N/A" {
			x.IPV = r.IPV
		}
		if x.Protocol == "" || x.Protocol == "N/A" {
			x.Protocol = r.Protocol
		}
	}

	for _, r := range bRows {
		x, ok := m[r.TGID]
		if !ok {
			x = &acc{defaultStatusRow: defaultStatusRow{
				TGID:     r.TGID,
				SrcPort:  "N/A",
				DstPort:  "N/A",
				IPV:      "N/A",
				Protocol: r.Protocol,
			}}
			m[r.TGID] = x
		}
		portBytes := r.InBytes + r.OutBytes
		if portBytes >= x.portBytes {
			x.portBytes = portBytes
			x.SrcPort = nz(r.SPort)
			x.DstPort = nz(r.DPort)
			if x.Protocol == "" || x.Protocol == "N/A" {
				x.Protocol = r.Protocol
			}
		}
	}

	out := make([]defaultStatusRow, 0, len(m))
	for _, v := range m {
		out = append(out, v.defaultStatusRow)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TGID < out[j].TGID })
	return out, nil
}

func summarizeLeanStatus(path string) ([]defaultStatusRow, error) {
	rows, err := parseLeanTSV(path)
	if err != nil {
		return nil, err
	}
	out := make([]defaultStatusRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, defaultStatusRow{
			TGID:       r.TGID,
			BytesIn:    r.InBytes,
			BytesOut:   r.OutBytes,
			PacketsIn:  r.InPackets,
			PacketsOut: r.OutPackets,
			SrcPort:    "N/A",
			DstPort:    "N/A",
			IPV:        "N/A",
			Protocol:   "N/A",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TGID < out[j].TGID })
	return out, nil
}

func summarizeGreedyStatus(path string) ([]greedyStatusRow, error) {
	rows, err := parseGreedyTSV(path)
	if err != nil {
		return nil, err
	}

	type acc struct {
		greedyStatusRow
		topBytes int64
	}
	m := map[string]*acc{}
	for _, r := range rows {
		x, ok := m[r.TGID]
		if !ok {
			x = &acc{greedyStatusRow: greedyStatusRow{
				TGID:     r.TGID,
				SrcPort:  "N/A",
				DstPort:  "N/A",
				SAddr:    "N/A",
				DAddr:    "N/A",
				IPV:      r.IPV,
				Protocol: r.Protocol,
			}}
			m[r.TGID] = x
		}
		x.BytesIn += r.InBytes
		x.BytesOut += r.OutBytes
		x.PacketsIn += r.InPackets
		x.PacketsOut += r.OutPackets
		flowBytes := r.InBytes + r.OutBytes
		if flowBytes >= x.topBytes {
			x.topBytes = flowBytes
			x.SrcPort = nz(r.SPort)
			x.DstPort = nz(r.DPort)
			x.SAddr = nz(r.SAddr)
			x.DAddr = nz(r.DAddr)
			x.IPV = nz(r.IPV)
			x.Protocol = nz(r.Protocol)
		}
	}

	out := make([]greedyStatusRow, 0, len(m))
	for _, v := range m {
		out = append(out, v.greedyStatusRow)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TGID < out[j].TGID })
	return out, nil
}

func nz(s string) string {
	if strings.TrimSpace(s) == "" {
		return "N/A"
	}
	return s
}
