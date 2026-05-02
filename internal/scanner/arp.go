package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ArpEntry represents a device found via ARP.
type ArpEntry struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
	OUI string `json:"oui,omitempty"`
}

// ArpScan discovers devices by reading the system ARP table.
// On macOS/Linux, it first does a TCP-dial sweep to populate the ARP cache,
// then reads the ARP table.
func ArpScan(cidr string) ([]ArpEntry, error) {
	pingSweep(cidr)
	return readArpTable(cidr)
}

// pingSweep sends TCP-dial probes to populate the system ARP cache.
// We use TCP-dial rather than ICMP to avoid root requirements.
func pingSweep(cidr string) {
	hosts, err := enumerateHosts(cidr)
	if err != nil {
		return
	}

	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup

	for _, ip := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, port := range []int{80, 502, 443} {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", addr, port), 200*time.Millisecond)
				if err == nil {
					conn.Close()
					return
				}
			}
		}(ip.String())
	}

	wg.Wait()
}

// readArpTable reads the system ARP table and filters entries within the given CIDR.
func readArpTable(cidr string) ([]ArpEntry, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var entries []ArpEntry

	switch runtime.GOOS {
	case "darwin":
		entries, err = readArpDarwin()
	case "linux":
		entries, err = readArpLinux()
	default:
		entries, err = readArpDarwin() // fallback (works on BSD-likes too)
	}
	if err != nil {
		return nil, err
	}

	var filtered []ArpEntry
	for _, e := range entries {
		ip := net.ParseIP(e.IP)
		if ip != nil && ipnet.Contains(ip) {
			filtered = append(filtered, e)
		}
	}

	return filtered, nil
}

// macOS: parse `arp -a` output
// Format: host (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
var arpDarwinRe = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)`)

func readArpDarwin() ([]ArpEntry, error) {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("arp -a: %w", err)
	}

	var entries []ArpEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		matches := arpDarwinRe.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}
		mac := matches[2]
		if mac == "(incomplete)" || mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		entries = append(entries, ArpEntry{
			IP:  matches[1],
			MAC: normalizeMAC(mac),
			OUI: extractOUI(mac),
		})
	}

	return entries, nil
}

// Linux: read /proc/net/arp directly (no exec needed).
// Format: IP address  HW type  Flags  HW address  Mask  Device
func readArpLinux() ([]ArpEntry, error) {
	out, err := exec.Command("cat", "/proc/net/arp").Output()
	if err != nil {
		return readArpDarwin()
	}

	var entries []ArpEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		mac := fields[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		entries = append(entries, ArpEntry{
			IP:  fields[0],
			MAC: normalizeMAC(mac),
			OUI: extractOUI(mac),
		})
	}

	return entries, nil
}

// normalizeMAC formats a MAC address consistently.
func normalizeMAC(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return mac
	}
	return hw.String()
}

// extractOUI returns the first 3 bytes (vendor prefix) of a MAC address.
func extractOUI(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 3 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x", hw[0], hw[1], hw[2])
}
