// Package scanner discovers devices on the local LAN. It does
// concurrent TCP-dial probes across a CIDR for a list of ports, plus
// optional ARP-table reads + HTTP banner grabs. No raw sockets — uses
// only stdlib net.Dial and `arp -a` / /proc/net/arp.
package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Interface represents a network interface with its subnets.
type Interface struct {
	Name    string   `json:"name"`
	Subnets []string `json:"subnets"`
}

// Host represents a discovered host with an open port.
type Host struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Duration string `json:"duration"`
}

// DefaultPorts are common Modbus TCP and MQTT ports to scan.
var DefaultPorts = []int{502, 1502, 8899, 6607, 80, 443, 1883, 8080}

// GetInterfaces returns all non-loopback network interfaces with IPv4 subnets.
func GetInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var subnets []string
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			network := ipnet.IP.Mask(ipnet.Mask)
			ones, _ := ipnet.Mask.Size()
			subnets = append(subnets, fmt.Sprintf("%s/%d", network.String(), ones))
		}
		if len(subnets) > 0 {
			result = append(result, Interface{Name: iface.Name, Subnets: subnets})
		}
	}
	return result, nil
}

// LocalCIDR returns a best-effort /24 covering the host's primary
// non-loopback interface. Falls back to "192.168.1.0/24" if nothing is
// found. Used when the agent receives a scan request with no CIDR.
func LocalCIDR() string {
	ifaces, err := GetInterfaces()
	if err != nil {
		return "192.168.1.0/24"
	}
	for _, iface := range ifaces {
		for _, subnet := range iface.Subnets {
			// Force /24 even if the interface is /16 — full /16 sweep is too slow.
			_, ipnet, err := net.ParseCIDR(subnet)
			if err != nil {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if ones < 24 {
				// Take the first three octets, mask /24.
				ip := ipnet.IP.To4()
				if ip == nil {
					continue
				}
				return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
			}
			return subnet
		}
	}
	return "192.168.1.0/24"
}

// ScanSubnetMultiPort scans a subnet for multiple ports.
func ScanSubnetMultiPort(cidr string, ports []int, timeout time.Duration) ([]Host, error) {
	hosts, err := enumerateHosts(cidr)
	if err != nil {
		return nil, err
	}

	var allResults []Host
	for _, port := range ports {
		results := scanHosts(hosts, port, timeout)
		allResults = append(allResults, results...)
	}

	seen := make(map[string]bool)
	var deduped []Host
	for _, h := range allResults {
		key := fmt.Sprintf("%s:%d", h.IP, h.Port)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, h)
		}
	}

	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].IP == deduped[j].IP {
			return deduped[i].Port < deduped[j].Port
		}
		return deduped[i].IP < deduped[j].IP
	})

	return deduped, nil
}

func enumerateHosts(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var hosts []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		hostIP := make(net.IP, len(ip))
		copy(hostIP, ip)
		hosts = append(hosts, hostIP)
	}

	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func scanHosts(hosts []net.IP, port int, timeout time.Duration) []Host {
	maxConcurrent := 256
	sem := make(chan struct{}, maxConcurrent)

	var mu sync.Mutex
	var results []Host
	var wg sync.WaitGroup

	for _, hostIP := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", ip, port)
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, timeout)
			duration := time.Since(start)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			results = append(results, Host{
				IP:       ip,
				Port:     port,
				Duration: fmt.Sprintf("%dms", duration.Milliseconds()),
			})
			mu.Unlock()
		}(hostIP.String())
	}

	wg.Wait()
	return results
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
