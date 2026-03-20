package main

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func handleStatus(s *state, cl *client) {
	reply(cl.w, "status", true, "", s.statusData())
	endPacket(cl.w)
}

func handleTTL(s *state, cl *client, f []string) {
	if len(f) == 1 {
		stateName, remain := s.toggleTTL()
		reply(cl.w, "ttl", true, "", map[string]any{
			"ttl_state":             stateName,
			"ttl_remaining_seconds": remain,
		})
		reply(cl.w, "status", true, "", s.statusData())
		endPacket(cl.w)
		return
	}

	if len(f) == 2 {
		n, err := strconv.Atoi(f[1])
		if err != nil || n < 0 {
			reply(cl.w, "error", false, "usage: TTL <MINUTES>", nil)
			endPacket(cl.w)
			return
		}
		s.setTTL(n)
		reply(cl.w, "ttl", true, "", map[string]any{
			"ttl_state":             "on",
			"ttl_remaining_seconds": int64((time.Duration(n) * time.Minute) / time.Second),
		})
		reply(cl.w, "status", true, "", s.statusData())
		endPacket(cl.w)
		return
	}

	reply(cl.w, "error", false, "invalid TTL command", nil)
	endPacket(cl.w)
}

func handlePS(s *state, cl *client, f []string) {
	if len(f) == 1 {
		rows, err := runPS(s.psPath)
		if err != nil {
			reply(cl.w, "error", false, "ps failed", nil)
			endPacket(cl.w)
			return
		}

		reply(cl.w, "ps_summary", true, "", map[string]any{
			"rows_total": len(rows),
			"rows_shown": len(rows),
		})
		for _, row := range rows {
			reply(cl.w, "ps_row", true, "", map[string]any{
				"pid": row.PID, "tgid": row.TGID, "uid": row.UID, "threads": row.Thr, "comm": row.Comm,
			})
		}
		endPacket(cl.w)
		return
	}

	if len(f) == 2 {
		if n, err := strconv.Atoi(f[1]); err == nil && n >= 0 {
			rows, err := runPS(s.psPath)
			if err != nil {
				reply(cl.w, "error", false, "ps failed", nil)
				endPacket(cl.w)
				return
			}

			show := n
			if show > len(rows) {
				show = len(rows)
			}

			reply(cl.w, "ps_summary", true, "", map[string]any{
				"rows_total": len(rows),
				"rows_shown": show,
			})
			for i := 0; i < show; i++ {
				row := rows[i]
				reply(cl.w, "ps_row", true, "", map[string]any{
					"pid": row.PID, "tgid": row.TGID, "uid": row.UID, "threads": row.Thr, "comm": row.Comm,
				})
			}
			endPacket(cl.w)
			return
		}

		if strings.EqualFold(f[1], "apps") {
			rows, err := readPS(s.psPath)
			if err != nil {
				reply(cl.w, "error", false, "no snapshot available", nil)
				endPacket(cl.w)
				return
			}

			groups := groupApps(rows)
			reply(cl.w, "ps_apps", true, "", map[string]any{"count": len(groups)})
			for _, g := range groups {
				reply(cl.w, "ps_app", true, "", map[string]any{"name": g.Comm})
			}
			endPacket(cl.w)
			return
		}
	}

	if len(f) >= 3 && strings.EqualFold(f[1], "find") {
		rows, err := readPS(s.psPath)
		if err != nil {
			reply(cl.w, "error", false, "no snapshot available", nil)
			endPacket(cl.w)
			return
		}

		query := strings.Join(f[2:], " ")
		found, total := psFind(rows, query, 50)

		reply(cl.w, "ps_find", true, "", map[string]any{
			"query": query, "rows_total": total, "rows_shown": len(found),
		})
		for _, row := range found {
			reply(cl.w, "ps_row", true, "", map[string]any{
				"pid": row.PID, "tgid": row.TGID, "uid": row.UID, "threads": row.Thr, "comm": row.Comm,
			})
		}
		endPacket(cl.w)
		return
	}

	if len(f) == 3 && strings.EqualFold(f[1], "t") {
		if strings.EqualFold(f[2], "on") {
			s.mu.Lock()
			s.psTimerOn = true
			s.mu.Unlock()
			reply(cl.w, "ack", true, "ps timer on", nil)
			endPacket(cl.w)
			return
		}

		if strings.EqualFold(f[2], "off") {
			s.mu.Lock()
			s.psTimerOn = false
			s.mu.Unlock()
			reply(cl.w, "ack", true, "ps timer off", nil)
			endPacket(cl.w)
			return
		}

		n, err := strconv.Atoi(f[2])
		if err != nil || n <= 0 {
			reply(cl.w, "error", false, "usage: PS T <SECONDS>", nil)
			endPacket(cl.w)
			return
		}

		s.mu.Lock()
		s.psSeconds = n
		s.mu.Unlock()
		reply(cl.w, "ack", true, "ps timer updated", nil)
		endPacket(cl.w)
		return
	}

	reply(cl.w, "error", false, "invalid PS command", nil)
	endPacket(cl.w)
}

func parseModeAndRest(f []string, idx int) (string, int) {
	if len(f) > idx {
		switch strings.ToLower(f[idx]) {
		case "default":
			return "default", idx + 1
		case "lean":
			return "lean", idx + 1
		case "greedy":
			return "greedy", idx + 1
		}
	}
	return "default", idx
}

func recTGIDSet(rec monitorRecord) map[string]struct{} {
	set := make(map[string]struct{}, len(rec.TGIDs))
	for _, t := range rec.TGIDs {
		set[t] = struct{}{}
	}
	return set
}

func allowTGID(set map[string]struct{}, tgid string) bool {
	if tgid == "" || tgid == "0" {
		return false
	}
	_, ok := set[tgid]
	return ok
}

func emitCGMStatusData(cl *client, rec monitorRecord) {
	allowed := recTGIDSet(rec)

	reply(cl.w, "cgm_status_meta", true, "", map[string]any{
		"name":    rec.Name,
		"mode":    rec.Mode,
		"active":  rec.Active,
		"count":   len(rec.TGIDs),
		"tgids":   rec.TGIDs,
		"archive": rec.LastArchivePath,
	})

	switch rec.Mode {
	case "lean":
		rows, err := summarizeLeanStatus(rec.OutputPath)
		if err != nil {
			reply(cl.w, "error", false, "unable to read cgm output", nil)
			return
		}
		for _, r := range rows {
			if !allowTGID(allowed, r.TGID) {
				continue
			}
			reply(cl.w, "cgm_status_row", true, "", map[string]any{
				"tgid":        r.TGID,
				"bytes_in":    fmt.Sprintf("%d", r.BytesIn),
				"bytes_out":   fmt.Sprintf("%d", r.BytesOut),
				"packets_in":  fmt.Sprintf("%d", r.PacketsIn),
				"packets_out": fmt.Sprintf("%d", r.PacketsOut),
				"src_port":    r.SrcPort,
				"dst_port":    r.DstPort,
				"ipv":         r.IPV,
				"protocol":    r.Protocol,
			})
		}

	case "greedy":
		rows, err := summarizeGreedyStatus(rec.OutputPath)
		if err != nil {
			reply(cl.w, "error", false, "unable to read cgm output", nil)
			return
		}
		for _, r := range rows {
			if !allowTGID(allowed, r.TGID) {
				continue
			}
			reply(cl.w, "cgm_status_row", true, "", map[string]any{
				"tgid":        r.TGID,
				"bytes_in":    fmt.Sprintf("%d", r.BytesIn),
				"bytes_out":   fmt.Sprintf("%d", r.BytesOut),
				"packets_in":  fmt.Sprintf("%d", r.PacketsIn),
				"packets_out": fmt.Sprintf("%d", r.PacketsOut),
				"src_port":    r.SrcPort,
				"dst_port":    r.DstPort,
				"ipv":         r.IPV,
				"protocol":    r.Protocol,
				"saddr":       r.SAddr,
				"daddr":       r.DAddr,
			})
		}

	default:
		rows, err := summarizeDefaultStatus(rec.OutputPath)
		if err != nil {
			reply(cl.w, "error", false, "unable to read cgm output", nil)
			return
		}
		for _, r := range rows {
			if !allowTGID(allowed, r.TGID) {
				continue
			}
			reply(cl.w, "cgm_status_row", true, "", map[string]any{
				"tgid":        r.TGID,
				"bytes_in":    fmt.Sprintf("%d", r.BytesIn),
				"bytes_out":   fmt.Sprintf("%d", r.BytesOut),
				"packets_in":  fmt.Sprintf("%d", r.PacketsIn),
				"packets_out": fmt.Sprintf("%d", r.PacketsOut),
				"src_port":    r.SrcPort,
				"dst_port":    r.DstPort,
				"ipv":         r.IPV,
				"protocol":    r.Protocol,
			})
		}
	}
}

func runAndRegisterCGM(s *state, cl *client, logical, mode string, tgids []string, heartbeatManaged bool) {
	res, err := runCGMMode(s.instance, logical, mode, tgids, s.cgmDir, s.archiveDir, s.logOut, s.logErr)
	if err != nil {
		reply(cl.w, "error", false, "cgm failed", nil)
		endPacket(cl.w)
		return
	}

	rec := monitorRecord{
		Name:             logical,
		Internal:         namespacedCGMName(s.instance, logical),
		Mode:             mode,
		TGIDs:            tgids,
		OutputPath:       res.OutputPath,
		LastArchivePath:  res.ArchivePath,
		Active:           true,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
		HeartbeatManaged: heartbeatManaged,
	}
	_ = upsertRegistryRecord(s.registryPath, rec)

	reply(cl.w, "cgm_summary", true, "", map[string]any{
		"name":    logical,
		"mode":    mode,
		"count":   len(tgids),
		"tgids":   tgids,
		"archive": res.ArchivePath,
	})
	emitCGMStatusData(cl, rec)
	endPacket(cl.w)
}

func handleCGM(s *state, cl *client, f []string) {
	if len(f) < 2 {
		reply(cl.w, "error", false, "usage: CGM <APP>", nil)
		endPacket(cl.w)
		return
	}

	if strings.EqualFold(f[1], "status") {
		if len(f) == 2 {
			recs, err := activeRegistry(s.registryPath)
			if err != nil {
				reply(cl.w, "error", false, "registry load failed", nil)
				endPacket(cl.w)
				return
			}
			reply(cl.w, "cgm_registry", true, "", map[string]any{"count": len(recs)})
			for _, rec := range recs {
				reply(cl.w, "cgm_registry_item", true, "", map[string]any{
					"name":    rec.Name,
					"mode":    rec.Mode,
					"active":  rec.Active,
					"count":   len(rec.TGIDs),
					"archive": rec.LastArchivePath,
				})
			}
			endPacket(cl.w)
			return
		}

		name := strings.Join(f[2:], " ")
		rec, err := findRegistryByName(s.registryPath, name)
		if err != nil || rec == nil {
			reply(cl.w, "error", false, "monitor not found", nil)
			endPacket(cl.w)
			return
		}

		refreshed, err := refreshCGMMode(s.instance, *rec, s.archiveDir, s.logOut, s.logErr)
		if err == nil && refreshed != nil {
			rec.OutputPath = refreshed.OutputPath
			rec.LastArchivePath = refreshed.ArchivePath
			rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			_ = upsertRegistryRecord(s.registryPath, *rec)
		}

		emitCGMStatusData(cl, *rec)
		endPacket(cl.w)
		return
	}

	if strings.EqualFold(f[1], "stop") {
		if len(f) == 3 && strings.EqualFold(f[2], "all") {
			recs, err := activeRegistry(s.registryPath)
			if err != nil {
				reply(cl.w, "error", false, "registry load failed", nil)
				endPacket(cl.w)
				return
			}
			names := []string{}
			for _, rec := range recs {
				_ = stopMonitor(s.instance, s.archiveDir, s.registryPath, rec)
				names = append(names, rec.Name)
			}
			reply(cl.w, "ack", true, "all monitors stopped", map[string]any{"names": names})
			reply(cl.w, "status", true, "", s.statusData())
			endPacket(cl.w)
			return
		}

		name := strings.Join(f[2:], " ")
		rec, err := findRegistryByName(s.registryPath, name)
		if err != nil || rec == nil {
			reply(cl.w, "error", false, "monitor not found", nil)
			endPacket(cl.w)
			return
		}
		if err := stopMonitor(s.instance, s.archiveDir, s.registryPath, *rec); err != nil {
			reply(cl.w, "error", false, "monitor stop failed", nil)
			endPacket(cl.w)
			return
		}
		reply(cl.w, "ack", true, "monitor stopped", nil)
		endPacket(cl.w)
		return
	}

	if strings.EqualFold(f[1], "lt") && len(f) >= 3 && strings.EqualFold(f[2], "stop") {
		targets := dedupe(f[3:])
		recs, err := activeRegistry(s.registryPath)
		if err != nil {
			reply(cl.w, "error", false, "registry load failed", nil)
			endPacket(cl.w)
			return
		}

		stopped := []string{}
		targetSet := map[string]struct{}{}
		for _, t := range targets {
			targetSet[t] = struct{}{}
		}

		for _, rec := range recs {
			hit := false
			for _, t := range rec.TGIDs {
				if _, ok := targetSet[t]; ok {
					hit = true
					break
				}
			}
			if hit {
				_ = stopMonitor(s.instance, s.archiveDir, s.registryPath, rec)
				stopped = append(stopped, rec.Name)
			}
		}

		reply(cl.w, "ack", true, "tgid monitor stop complete", map[string]any{"names": stopped})
		endPacket(cl.w)
		return
	}

	rows, err := readPS(s.psPath)
	if err != nil {
		reply(cl.w, "error", false, "no snapshot available", nil)
		endPacket(cl.w)
		return
	}
	groups := groupApps(rows)

	if len(f) >= 3 && strings.EqualFold(f[1], "strict") {
		mode, idx := parseModeAndRest(f, 2)
		if len(f) <= idx {
			reply(cl.w, "error", false, "usage: CGM STRICT [DEFAULT|LEAN|GREEDY] <APP>", nil)
			endPacket(cl.w)
			return
		}
		app := strings.Join(f[idx:], " ")
		g := appExact(groups, app)
		if g == nil || len(g.TGIDs) == 0 {
			reply(cl.w, "error", false, "no exact process match", nil)
			endPacket(cl.w)
			return
		}
		runAndRegisterCGM(s, cl, g.Comm, mode, g.TGIDs, false)
		return
	}

	if len(f) >= 3 && strings.EqualFold(f[1], "ls") {
		mode, idx := parseModeAndRest(f, 2)
		if len(f) <= idx {
			reply(cl.w, "error", false, "usage: CGM LS [DEFAULT|LEAN|GREEDY] <APP> [APP...]", nil)
			endPacket(cl.w)
			return
		}
		all := make([]string, 0)
		label := make([]string, 0)
		for _, name := range f[idx:] {
			g := appExact(groups, name)
			if g == nil {
				continue
			}
			all = append(all, g.TGIDs...)
			label = append(label, g.Comm)
		}
		all = dedupe(all)
		if len(all) == 0 {
			reply(cl.w, "error", false, "no exact app list matches", nil)
			endPacket(cl.w)
			return
		}
		runAndRegisterCGM(s, cl, strings.Join(label, "_"), mode, all, false)
		return
	}

	if len(f) >= 3 && strings.EqualFold(f[1], "lt") {
		mode, idx := parseModeAndRest(f, 2)
		if len(f) <= idx {
			reply(cl.w, "error", false, "usage: CGM LT [DEFAULT|LEAN|GREEDY] <TGID> [TGID...]", nil)
			endPacket(cl.w)
			return
		}
		tgids := dedupe(f[idx:])
		runAndRegisterCGM(s, cl, "tgid_batch", mode, tgids, false)
		return
	}

	mode, idx := parseModeAndRest(f, 1)
	if len(f) <= idx {
		reply(cl.w, "error", false, "usage: CGM [DEFAULT|LEAN|GREEDY] <APP>", nil)
		endPacket(cl.w)
		return
	}
	app := strings.Join(f[idx:], " ")
	matches := appPrefix(groups, app)
	if len(matches) == 0 {
		reply(cl.w, "error", false, "no process prefix match", nil)
		endPacket(cl.w)
		return
	}

	all := make([]string, 0)
	name := strings.TrimSpace(app)
	if name == "" {
		name = matches[0].Comm
	}
	for _, g := range matches {
		all = append(all, g.TGIDs...)
	}
	all = dedupe(all)
	runAndRegisterCGM(s, cl, name, mode, all, false)
}

func handleHeartbeat(s *state, cl *client, f []string) {
	if len(f) == 1 || (len(f) == 2 && strings.EqualFold(f[1], "status")) {
		stateName := "off"
		if s.heartbeatOn {
			stateName = "on"
		}
		reply(cl.w, "heartbeat_status", true, "", map[string]any{
			"state":   stateName,
			"seconds": s.heartbeatSeconds,
			"top_n":   s.heartbeatTopN,
			"summary": s.heartbeatSummary,
		})
		endPacket(cl.w)
		return
	}

	if len(f) == 2 && strings.EqualFold(f[1], "on") {
		s.mu.Lock()
		s.heartbeatOn = true
		s.mu.Unlock()
		reply(cl.w, "ack", true, "heartbeat on", nil)
		reply(cl.w, "status", true, "", s.statusData())
		endPacket(cl.w)
		return
	}

	if len(f) == 2 && strings.EqualFold(f[1], "off") {
		s.mu.Lock()
		s.heartbeatOn = false
		s.mu.Unlock()
		reply(cl.w, "ack", true, "heartbeat off", nil)
		reply(cl.w, "status", true, "", s.statusData())
		endPacket(cl.w)
		return
	}

	if len(f) == 2 {
		n, err := strconv.Atoi(f[1])
		if err == nil && n > 0 {
			s.mu.Lock()
			s.heartbeatSeconds = n
			s.mu.Unlock()
			reply(cl.w, "ack", true, "heartbeat interval updated", nil)
			endPacket(cl.w)
			return
		}
	}

	if len(f) == 3 && strings.EqualFold(f[1], "top") {
		n, err := strconv.Atoi(f[2])
		if err != nil || n <= 0 {
			reply(cl.w, "error", false, "usage: HEARTBEAT TOP <N>", nil)
			endPacket(cl.w)
			return
		}
		s.mu.Lock()
		s.heartbeatTopN = n
		s.mu.Unlock()
		reply(cl.w, "ack", true, "heartbeat top updated", nil)
		reply(cl.w, "status", true, "", s.statusData())
		endPacket(cl.w)
		return
	}

	reply(cl.w, "error", false, "invalid HEARTBEAT command", nil)
	endPacket(cl.w)
}

func handleClient(s *state, conn net.Conn) {
	cl := &client{
		conn: conn,
		w:    bufio.NewWriter(conn),
		uid:  peerUID(conn),
	}
	s.addClient(cl)
	defer s.delClient(cl)

	reply(cl.w, "hello", true, "", map[string]any{
		"instance":   s.instance,
		"visibility": s.visibility,
		"owner_uid":  s.ownerUID,
	})
	reply(cl.w, "status", true, "", s.statusData())
	endPacket(cl.w)

	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}

		switch strings.ToLower(f[0]) {
		case "status":
			handleStatus(s, cl)
		case "ttl":
			handleTTL(s, cl, f)
		case "ps":
			handlePS(s, cl, f)
		case "cgm":
			handleCGM(s, cl, f)
		case "heartbeat":
			handleHeartbeat(s, cl, f)
		case "kill":
			reply(cl.w, "ack", true, "killing server", nil)
			endPacket(cl.w)
			go s.shutdown()
			return
		default:
			reply(cl.w, "error", false, "unknown command", nil)
			endPacket(cl.w)
		}
	}
}
