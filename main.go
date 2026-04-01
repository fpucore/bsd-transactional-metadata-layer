package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const installerVersion = "1.0.0"

// ─────────────────────────────────────────────
// BSD Config
// ─────────────────────────────────────────────

type bsdConfig struct {
	name          string
	rootDir       string
	releasesURL   string
	versionRegex  string
	unameBinary   string
	elfOsAbi      byte
	elfNoteTag    string
	baseURLFunc   func(version string) string
	kernelURLFunc func(version string) string
}

var bsdConfigs = map[string]bsdConfig{
	"netbsd": {
		name:         "NetBSD",
		rootDir:      "NetBSD",
		releasesURL:  "https://www.netbsd.org/releases/",
		versionRegex: `NetBSD\s+[0-9]+\.[0-9]+`,
		unameBinary:  "netbsd_uname",
		elfOsAbi:     0x09,
		elfNoteTag:   "NetBSD",
		baseURLFunc: func(version string) string {
			v := extractVersionNumber(version)
			if v == "" {
				return ""
			}
			return "https://cdn.netbsd.org/pub/NetBSD/NetBSD-" + v + "/amd64/binary/sets/base.tar.xz"
		},
		kernelURLFunc: func(version string) string {
			v := extractVersionNumber(version)
			if v == "" {
				return ""
			}
			return "https://cdn.netbsd.org/pub/NetBSD/NetBSD-" + v + "/amd64/binary/kernel/netbsd-GENERIC.gz"
		},
	},
	"openbsd": {
		name:         "OpenBSD",
		rootDir:      "OpenBSD",
		releasesURL:  "https://www.openbsd.org/",
		versionRegex: `OpenBSD\s+[0-9]+\.[0-9]+`,
		unameBinary:  "openbsd_uname",
		elfOsAbi:     0x00,
		elfNoteTag:   "OpenBSD",
		baseURLFunc: func(version string) string {
			v := extractVersionNumber(version)
			if v == "" {
				return ""
			}
			noDot := strings.ReplaceAll(v, ".", "")
			return "https://cdn.openbsd.org/pub/OpenBSD/" + v + "/amd64/base" + noDot + ".tgz"
		},
		kernelURLFunc: func(version string) string {
			v := extractVersionNumber(version)
			if v == "" {
				return ""
			}
			return "https://cdn.openbsd.org/pub/OpenBSD/" + v + "/amd64/bsd"
		},
	},
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func extractVersionNumber(s string) string {
	re := regexp.MustCompile(`[0-9]+\.[0-9]+`)
	return re.FindString(s)
}

func versionToInt(v string) uint32 {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return uint32(major*100000000 + minor*1000000)
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

func fetchText(url string) (string, error) {
	resp, err := httpClient().Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func fetchVersion(url, pattern string) (string, error) {
	page, err := fetchText(url)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(pattern)
	match := re.FindString(page)
	if match == "" {
		return "", fmt.Errorf("version not found on page")
	}
	return strings.TrimSpace(match) + " GENERIC amd64", nil
}

func fetchContentLength(url string) (int64, error) {
	if url == "" {
		return 0, fmt.Errorf("no URL configured")
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := httpClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("HTTP %s", resp.Status)
	}

	if resp.ContentLength > 0 {
		return resp.ContentLength, nil
	}

	cl := resp.Header.Get("Content-Length")
	if cl == "" {
		return 0, fmt.Errorf("content-length not provided")
	}

	return strconv.ParseInt(cl, 10, 64)
}

func writeStringFile(path, value string) error {
	return os.WriteFile(path, []byte(value+"\n"), 0644)
}

// fixFishPath ensures ~/.local/bin is in the Fish shell path.
func fixFishPath() {
	_, err := exec.LookPath("fish")
	if err != nil {
		return // Fish not found
	}

	cmd := exec.Command("fish", "-c", "set -Ua fish_user_paths ~/.local/bin")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: could not update Fish path: %v\n", err)
	} else {
		fmt.Println("Updated Fish shell path (fish_user_paths).")
	}
}

// ─────────────────────────────────────────────
// ELF Kernel Builder
// ─────────────────────────────────────────────

func buildELFHeader(osAbi byte, noteOffset uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0x7f, 'E', 'L', 'F'})
	h[4] = 2     // 64-bit
	h[5] = 1     // Little Endian
	h[6] = 1     // Version
	h[7] = osAbi
	binary.LittleEndian.PutUint16(h[16:], 2)                   // ET_EXEC
	binary.LittleEndian.PutUint16(h[18:], 0x3e)                // x86-64
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint64(h[24:], 0xffffffff80200000)  // kernel load addr
	binary.LittleEndian.PutUint64(h[40:], noteOffset)
	binary.LittleEndian.PutUint16(h[52:], 64)
	binary.LittleEndian.PutUint16(h[54:], 56)
	binary.LittleEndian.PutUint16(h[58:], 64)
	binary.LittleEndian.PutUint16(h[60:], 1)
	return h
}

func buildNoteSection(tag string, version uint32) []byte {
	name := tag + "\x00"
	for len(name)%4 != 0 {
		name += "\x00"
	}
	note := make([]byte, 12+len(name)+4)
	binary.LittleEndian.PutUint32(note[0:], uint32(len(tag)+1))
	binary.LittleEndian.PutUint32(note[4:], 4)
	binary.LittleEndian.PutUint32(note[8:], 1)
	copy(note[12:], []byte(name))
	binary.LittleEndian.PutUint32(note[12+len(name):], version)
	return note
}

func buildSectionHeader(noteOffset, noteSize uint64) []byte {
	sh := make([]byte, 64)
	binary.LittleEndian.PutUint32(sh[4:], 7) // SHT_NOTE
	binary.LittleEndian.PutUint64(sh[24:], noteOffset)
	binary.LittleEndian.PutUint64(sh[32:], noteSize)
	return sh
}

func createKernel(path string, size int64, cfg bsdConfig, version string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	versionNum := versionToInt(extractVersionNumber(version))
	note := buildNoteSection(cfg.elfNoteTag, versionNum)
	noteOffset := uint64(64)
	shOffset := noteOffset + uint64(len(note))

	elfHeader := buildELFHeader(cfg.elfOsAbi, shOffset)
	sectionHeader := buildSectionHeader(noteOffset, uint64(len(note)))

	if _, err := f.Write(elfHeader); err != nil {
		return err
	}
	if _, err := f.Write(note); err != nil {
		return err
	}
	if _, err := f.Write(sectionHeader); err != nil {
		return err
	}
	return f.Truncate(size)
}

// ─────────────────────────────────────────────
// Tar Archive Builder
// ─────────────────────────────────────────────

func buildTarHeader(filename string) []byte {
	h := make([]byte, 512)
	copy(h[0:100], []byte(filename))
	copy(h[100:108], []byte("0000644\x00"))
	copy(h[257:263], []byte("ustar\x00"))
	checksum := 0
	for i := 0; i < 512; i++ {
		checksum += int(h[i])
	}
	copy(h[148:156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
	return h
}

func createArchive(path string, size int64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tarHeader := buildTarHeader("etc/release")
	if _, err := f.Write(tarHeader); err != nil {
		return err
	}
	return f.Truncate(size)
}

// ─────────────────────────────────────────────
// Installer
// ─────────────────────────────────────────────

func install(cfg bsdConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not get home dir: %w", err)
	}

	bsdRoot := filepath.Join(home, cfg.rootDir)
	binDir := filepath.Join(home, ".local", "bin")

	for _, d := range []string{"bin", "lib", "etc"} {
		if err := os.MkdirAll(filepath.Join(bsdRoot, d), 0755); err != nil {
			return fmt.Errorf("could not create dir: %w", err)
		}
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("could not create bin dir: %w", err)
	}

	fmt.Printf("Fetching latest %s version...\n", cfg.name)
	version, err := fetchVersion(cfg.releasesURL, cfg.versionRegex)
	if err != nil {
		version = cfg.name + " unknown GENERIC amd64"
		fmt.Printf("Warning: could not fetch version (%v), using fallback.\n", err)
	}

	kvPath := filepath.Join(bsdRoot, "kernel_version")
	if err := writeStringFile(kvPath, version); err != nil {
		return fmt.Errorf("could not write kernel_version: %w", err)
	}

	fmt.Printf("Fetching %s base set size...\n", cfg.name)
	baseSize := int64(0)
	baseURL := cfg.baseURLFunc(version)
	if baseURL != "" {
		if s, err := fetchContentLength(baseURL); err != nil {
			fmt.Printf("Warning: could not fetch base size (%v)\n", err)
		} else {
			baseSize = s
		}
	}

	basePath := filepath.Join(bsdRoot, "base")
	if baseSize > 0 {
		if err := createArchive(basePath, baseSize); err != nil {
			return fmt.Errorf("could not create base archive: %w", err)
		}
	} else {
		writeStringFile(basePath, "unknown")
	}

	fmt.Printf("Fetching %s kernel size...\n", cfg.name)
	kernelSize := int64(0)
	kernelURL := cfg.kernelURLFunc(version)
	if kernelURL != "" {
		if s, err := fetchContentLength(kernelURL); err != nil {
			fmt.Printf("Warning: could not fetch kernel size (%v)\n", err)
		} else {
			kernelSize = s
		}
	}

	kernelPath := filepath.Join(bsdRoot, "kernel")
	if kernelSize > 0 {
		if err := createKernel(kernelPath, kernelSize, cfg, version); err != nil {
			return fmt.Errorf("could not create kernel: %w", err)
		}
	} else {
		writeStringFile(kernelPath, "unknown")
	}

	unamePath := filepath.Join(binDir, cfg.unameBinary)
	unameScript := fmt.Sprintf("#!/bin/sh\ncat %q\n", kvPath)
	if err := os.WriteFile(unamePath, []byte(unameScript), 0755); err != nil {
		return fmt.Errorf("could not write uname script: %w", err)
	}

	// Fix Fish path if necessary
	fixFishPath()

	fmt.Printf("\nInstalled %s environment.\n", cfg.name)
	fmt.Printf("Version  : %s\n", version)
	fmt.Printf("Root     : %s\n", bsdRoot)
	fmt.Printf("base     : %d bytes (sparse)\n", baseSize)
	fmt.Printf("kernel   : %d bytes (sparse ELF)\n", kernelSize)
	fmt.Printf("Command  : %s\n", unamePath)

	return nil
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

func main() {
	osFlag := flag.String("os", "", "BSD variant to install: netbsd or openbsd")
	versionFlag := flag.Bool("version", false, "Print installer version and exit")
	flag.BoolVar(versionFlag, "v", false, "Print installer version and exit (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "bsd_installer %s\n\n", installerVersion)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s --os <netbsd|openbsd>   Install a BSD environment\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --version               Print installer version\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --help                  Show this help message\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("bsd_installer version %s\n", installerVersion)
		os.Exit(0)
	}

	if *osFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --os flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	cfg, ok := bsdConfigs[strings.ToLower(*osFlag)]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: unknown OS %q. Choose netbsd or openbsd.\n", *osFlag)
		flag.Usage()
		os.Exit(1)
	}

	if err := install(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
