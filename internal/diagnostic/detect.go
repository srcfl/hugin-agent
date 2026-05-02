// Package diagnostic runs Modbus FC43 (Read Device Identification) and
// SunSpec common-model probes against a TCP-502 endpoint. It returns
// whatever vendor / model strings the device self-reports — driver
// matching is not done here (it lives in the web app).
package diagnostic

import (
	"fmt"
	"net"
	"time"

	"github.com/srcfl/hugin-agent/internal/modbus"
)

// TCPResult contains the result of a TCP connectivity test.
type TCPResult struct {
	Success  bool   `json:"success"`
	Duration string `json:"duration"`
	Error    string `json:"error,omitempty"`
}

// FC43Result contains what FC43 (Read Device Identification) reports.
type FC43Result struct {
	OK          bool   `json:"ok"`
	VendorName  string `json:"vendor_name,omitempty"`
	ProductCode string `json:"product_code,omitempty"`
	Revision    string `json:"revision,omitempty"`
	ProductName string `json:"product_name,omitempty"`
	ModelName   string `json:"model_name,omitempty"`
	SlaveID     byte   `json:"slave_id"`
	Error       string `json:"error,omitempty"`
}

// SunSpecResult contains what the SunSpec common model reports.
type SunSpecResult struct {
	OK           bool   `json:"ok"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Version      string `json:"version,omitempty"`
	BaseAddress  uint16 `json:"base_address,omitempty"`
	SlaveID      byte   `json:"slave_id"`
	Error        string `json:"error,omitempty"`
}

// TestTCP tests TCP connectivity to the given host:port.
func TestTCP(host string, port int) TCPResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	duration := time.Since(start)

	if err != nil {
		return TCPResult{
			Success:  false,
			Duration: fmt.Sprintf("%dms", duration.Milliseconds()),
			Error:    err.Error(),
		}
	}
	conn.Close()
	return TCPResult{
		Success:  true,
		Duration: fmt.Sprintf("%dms", duration.Milliseconds()),
	}
}

// ProbeFC43 tries Modbus FC43 (Read Device Identification) at the given
// host/port across a small list of candidate slave IDs and returns the
// first successful read. Pass slaveIDs == nil to use the default {1,0,247}.
func ProbeFC43(host string, port int, slaveIDs []byte) FC43Result {
	if len(slaveIDs) == 0 {
		slaveIDs = []byte{1, 0, 247}
	}

	for _, sid := range slaveIDs {
		client, err := modbus.NewTCPClientWithTimeout(host, port, sid, 500*time.Millisecond)
		if err != nil {
			continue
		}
		devID, err := client.ReadDeviceIdentification()
		client.Close()
		if err != nil || devID == nil {
			continue
		}
		if devID.VendorName == "" && devID.ProductCode == "" && devID.ProductName == "" {
			continue
		}
		return FC43Result{
			OK:          true,
			VendorName:  devID.VendorName,
			ProductCode: devID.ProductCode,
			Revision:    devID.Revision,
			ProductName: devID.ProductName,
			ModelName:   devID.ModelName,
			SlaveID:     sid,
		}
	}

	return FC43Result{OK: false, Error: "no device responded to FC43 on slave IDs " + sprintByteList(slaveIDs)}
}

// ProbeSunSpec tries SunSpec common-model discovery at the given host/port.
// Pass slaveIDs == nil to use the default {1,0,247}.
func ProbeSunSpec(host string, port int, slaveIDs []byte) SunSpecResult {
	if len(slaveIDs) == 0 {
		slaveIDs = []byte{1, 0, 247}
	}

	for _, sid := range slaveIDs {
		client, err := modbus.NewTCPClientWithTimeout(host, port, sid, 500*time.Millisecond)
		if err != nil {
			continue
		}
		info, err := client.DiscoverSunSpec()
		client.Close()
		if err != nil || info == nil {
			continue
		}
		return SunSpecResult{
			OK:           true,
			Manufacturer: info.Manufacturer,
			Model:        info.Model,
			Serial:       info.Serial,
			Version:      info.Version,
			BaseAddress:  info.BaseAddress,
			SlaveID:      sid,
		}
	}

	return SunSpecResult{OK: false, Error: "no SunSpec common model found on slave IDs " + sprintByteList(slaveIDs)}
}

func sprintByteList(b []byte) string {
	out := ""
	for i, v := range b {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%d", v)
	}
	return out
}
