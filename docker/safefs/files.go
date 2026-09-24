// Package safefs implements a deliberately small, read-only Linux MCP adapter.
package safefs

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"guardrail-proxy/security"
)

// Arguments accepts one canonical path and no unrecognized tool parameters.
type Arguments struct {
	Path string `json:"path"`
}

// Open walks directory descriptors with O_NOFOLLOW at every component. Renaming
// or replacing a symlink between checks cannot redirect the actual file open.
func Open(root, resource string) (*os.File, error) {
	relative, err := security.WorkspacePath(resource)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if relative != "" {
		parts := strings.Split(relative, "/")
		for i, part := range parts {
			flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
			if i < len(parts)-1 {
				flags |= syscall.O_DIRECTORY
			}
			next, e := syscall.Openat(fd, part, flags, 0)
			syscall.Close(fd)
			if e != nil {
				return nil, e
			}
			fd = next
		}
	}
	f := os.NewFile(uintptr(fd), "workspace-resource")
	info, err := f.Stat()
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		f.Close()
		return nil, errors.New("unsupported file type")
	}
	return f, nil
}

// Execute never writes, executes commands, follows symlinks or opens sockets.
func Execute(root, tool string, raw json.RawMessage) (string, error) {
	if tool != "read_text_file" && tool != "list_directory" {
		return "", errors.New("unknown tool")
	}
	var args Arguments
	if err := security.Decode(raw, &args); err != nil {
		return "", errors.New("invalid arguments")
	}
	f, err := Open(root, args.Path)
	if err != nil {
		return "", errors.New("resource unavailable")
	}
	defer f.Close()
	if tool == "list_directory" {
		entries, e := f.ReadDir(257)
		if e != nil && e != io.EOF {
			return "", errors.New("not a directory")
		}
		if len(entries) > 256 {
			return "", errors.New("directory budget exceeded")
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		b, _ := json.Marshal(names)
		return string(b), nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 || !utf8.Valid(b) {
		return "", errors.New("text budget or encoding invalid")
	}
	return string(b), nil
}
