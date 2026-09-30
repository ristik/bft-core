package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type archiveUsage struct {
	Records  uint64 `json:"records"`
	Bytes    uint64 `json:"bytes"`
	Scanned  uint64 `json:"scannedRecordDirectories"`
	Limit    uint64 `json:"recordDirectoryLimit"`
	Complete bool   `json:"complete"`
	Error    string `json:"error,omitempty"`
}

// measureArchive only scans record directories and their flat manifest/chunk
// files. ReadDir batches and a hard directory cap keep memory and work bounded.
func measureArchive(root string, limit uint64) archiveUsage {
	out := archiveUsage{Limit: limit, Complete: true}
	if root == "" {
		out.Complete = false
		out.Error = "archive directory is not configured"
		return out
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		out.Complete = false
		out.Error = err.Error()
		return out
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		out.Complete = false
		out.Error = "archive path is not a real directory"
		return out
	}
	dir, err := os.Open(root)
	if err != nil {
		out.Complete = false
		out.Error = err.Error()
		return out
	}
	defer dir.Close()
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			if !entry.IsDir() || !archiveRecordName(entry.Name()) {
				continue
			}
			if out.Scanned >= limit {
				out.Complete = false
				out.Error = "archive scan reached configured record-directory limit"
				return out
			}
			out.Scanned++
			out.Records++
			if err := addRecordBytes(root, entry.Name(), &out.Bytes); err != nil {
				out.Complete = false
				out.Error = err.Error()
				return out
			}
		}
		if errors.Is(readErr, io.EOF) {
			return out
		}
		if readErr != nil {
			out.Complete = false
			out.Error = readErr.Error()
			return out
		}
	}
}

func addRecordBytes(root, name string, total *uint64) error {
	dir, err := os.Open(filepath.Join(root, name))
	if err != nil {
		return err
	}
	defer dir.Close()
	for files := 0; ; {
		entries, readErr := dir.ReadDir(64)
		files += len(entries)
		if files > 64 {
			return fmt.Errorf("archive record %s contains more than 64 files", name)
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if info.Size() < 0 || uint64(info.Size()) > ^uint64(0)-*total {
				return fmt.Errorf("archive byte count overflow at record %s", name)
			}
			*total += uint64(info.Size())
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func archiveRecordName(name string) bool {
	if strings.HasPrefix(name, "v2-") {
		name = strings.TrimPrefix(name, "v2-")
	}
	if len(name) != 64 {
		return false
	}
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
