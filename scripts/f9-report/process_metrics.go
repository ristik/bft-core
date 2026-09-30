package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const maxProcessCommandOutput = 4 << 20

type processSnapshot struct {
	PID        int
	CPUSeconds float64
	RSSBytes   float64
	OpenFDs    uint64
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, fmt.Errorf("process command output exceeds %d bytes", b.limit)
	}
	return b.Buffer.Write(p)
}

func readProcessSnapshot(ctx context.Context, pidFile string) (*processSnapshot, error) {
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		return nil, fmt.Errorf("reading pid file: %w", err)
	}
	if len(pidBytes) > 64 {
		return nil, fmt.Errorf("pid file exceeds 64 bytes")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 0 {
		return nil, fmt.Errorf("invalid pid file contents")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	usage, err := runProcessCommand(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "time=", "-o", "rss=")
	if err != nil {
		return nil, fmt.Errorf("ps for pid %d: %w", pid, err)
	}
	cpu, rss, err := parsePSProcessStats(usage)
	if err != nil {
		return nil, fmt.Errorf("parsing ps output for pid %d: %w", pid, err)
	}
	var fds uint64
	switch runtime.GOOS {
	case "linux":
		fds, err = countEntries(filepath.Join("/proc", strconv.Itoa(pid), "fd"))
	case "darwin":
		var output []byte
		output, err = runProcessCommand(ctx, "lsof", "-Fn", "-p", strconv.Itoa(pid))
		if err == nil {
			fds, err = countLsofFDs(output)
		}
	default:
		err = fmt.Errorf("open-file count is unsupported on %s", runtime.GOOS)
	}
	if err != nil {
		return nil, fmt.Errorf("counting open files for pid %d: %w", pid, err)
	}
	return &processSnapshot{PID: pid, CPUSeconds: cpu, RSSBytes: rss * 1024, OpenFDs: fds}, nil
}

func runProcessCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout := &limitedBuffer{limit: maxProcessCommandOutput}
	stderr := &limitedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func parsePSProcessStats(output []byte) (cpuSeconds, rssKiB float64, err error) {
	fields := strings.Fields(string(output))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("expected CPU time and RSS fields")
	}
	cpuSeconds, err = parseCPUTime(fields[0])
	if err != nil {
		return 0, 0, err
	}
	rssKiB, err = strconv.ParseFloat(fields[1], 64)
	if err != nil || rssKiB < 0 {
		return 0, 0, fmt.Errorf("invalid RSS value %q", fields[1])
	}
	return cpuSeconds, rssKiB, nil
}

func parseCPUTime(value string) (float64, error) {
	days := 0.0
	if dayPart, rest, ok := strings.Cut(value, "-"); ok {
		parsed, err := strconv.ParseFloat(dayPart, 64)
		if err != nil || parsed < 0 {
			return 0, fmt.Errorf("invalid CPU day field %q", dayPart)
		}
		days, value = parsed, rest
	}
	parts := strings.Split(value, ":")
	if len(parts) < 1 || len(parts) > 3 {
		return 0, fmt.Errorf("invalid CPU time %q", value)
	}
	last, err := strconv.ParseFloat(parts[len(parts)-1], 64)
	if err != nil || last < 0 || last >= 60 && len(parts) > 1 {
		return 0, fmt.Errorf("invalid CPU seconds field %q", parts[len(parts)-1])
	}
	seconds := days*86400 + last
	if len(parts) >= 2 {
		minutes, parseErr := strconv.ParseFloat(parts[len(parts)-2], 64)
		if parseErr != nil || minutes < 0 || minutes >= 60 && len(parts) == 3 {
			return 0, fmt.Errorf("invalid CPU minutes field %q", parts[len(parts)-2])
		}
		seconds += minutes * 60
	}
	if len(parts) == 3 {
		hours, parseErr := strconv.ParseFloat(parts[0], 64)
		if parseErr != nil || hours < 0 {
			return 0, fmt.Errorf("invalid CPU hours field %q", parts[0])
		}
		seconds += hours * 3600
	}
	return seconds, nil
}

func countEntries(path string) (uint64, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, err
	}
	if len(entries) > maxProcessCommandOutput/16 {
		return 0, fmt.Errorf("open-file count exceeds configured bound")
	}
	return uint64(len(entries)), nil
}

func countLsofFDs(output []byte) (uint64, error) {
	const maxFDs = maxProcessCommandOutput / 16
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 256), maxProcessCommandOutput)
	var count uint64
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "f") && len(line) > 1 {
			count++
			if count > maxFDs {
				return 0, fmt.Errorf("open-file count exceeds configured bound")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}
