// Package modbus is a thin wrapper around goburrow/modbus that provides
// a thread-safe TCP client plus FC43 (Read Device Identification) and
// SunSpec common-model discovery. It's the only protocol code the agent
// ships with that talks raw to a device over TCP-502.
package modbus

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	mb "github.com/goburrow/modbus"
)

// Client wraps a Modbus TCP connection with thread-safe read access.
type Client struct {
	handler *mb.TCPClientHandler
	client  mb.Client
	mu      sync.Mutex
}

// NewTCPClient creates a Modbus TCP client connected to host:port with the given slave ID.
func NewTCPClient(host string, port int, slaveID byte) (*Client, error) {
	return NewTCPClientWithTimeout(host, port, slaveID, 5*time.Second)
}

// NewTCPClientWithTimeout creates a Modbus TCP client with a custom timeout.
func NewTCPClientWithTimeout(host string, port int, slaveID byte, timeout time.Duration) (*Client, error) {
	handler := mb.NewTCPClientHandler(net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	handler.Timeout = timeout
	handler.SlaveId = slaveID

	if err := handler.Connect(); err != nil {
		return nil, fmt.Errorf("modbus tcp connect %s:%d: %w", host, port, err)
	}

	return &Client{
		handler: handler,
		client:  mb.NewClient(handler),
	}, nil
}

// ReadInputRegisters reads count input registers starting at addr.
func (c *Client) ReadInputRegisters(addr, count uint16) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client.ReadInputRegisters(addr, count)
}

// ReadHoldingRegisters reads count holding registers starting at addr.
func (c *Client) ReadHoldingRegisters(addr, count uint16) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client.ReadHoldingRegisters(addr, count)
}

// ReadRegisters reads registers using the appropriate function code.
func (c *Client) ReadRegisters(addr, count uint16, holding bool) ([]byte, error) {
	if holding {
		return c.ReadHoldingRegisters(addr, count)
	}
	return c.ReadInputRegisters(addr, count)
}

// WriteSingleRegister writes a single holding register.
func (c *Client) WriteSingleRegister(addr, value uint16) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client.WriteSingleRegister(addr, value)
}

// WriteMultipleRegisters writes multiple holding registers starting at addr.
func (c *Client) WriteMultipleRegisters(addr uint16, values []uint16) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data := make([]byte, len(values)*2)
	for i, v := range values {
		data[i*2] = byte(v >> 8)
		data[i*2+1] = byte(v & 0xFF)
	}
	return c.client.WriteMultipleRegisters(addr, uint16(len(values)), data)
}

// Close closes the underlying Modbus connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handler.Close()
}

// SetSlaveID changes the slave ID for subsequent requests.
func (c *Client) SetSlaveID(id byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handler.SlaveId = id
}

// SendRawPDU sends a raw Modbus PDU (function code + data) and returns the response PDU.
func (c *Client) SendRawPDU(functionCode byte, data []byte) (respFunctionCode byte, respData []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pdu := &mb.ProtocolDataUnit{
		FunctionCode: functionCode,
		Data:         data,
	}
	adu, err := c.handler.Encode(pdu)
	if err != nil {
		return 0, nil, fmt.Errorf("encode: %w", err)
	}
	aduResp, err := c.handler.Send(adu)
	if err != nil {
		return 0, nil, fmt.Errorf("send: %w", err)
	}
	if err := c.handler.Verify(adu, aduResp); err != nil {
		return 0, nil, fmt.Errorf("verify: %w", err)
	}
	resp, err := c.handler.Decode(aduResp)
	if err != nil {
		return 0, nil, fmt.Errorf("decode: %w", err)
	}
	return resp.FunctionCode, resp.Data, nil
}

// DeviceIdentification holds the result of a Modbus FC 43/14 Read Device Identification request.
type DeviceIdentification struct {
	VendorName  string
	ProductCode string
	Revision    string
	VendorURL   string
	ProductName string
	ModelName   string
	UserAppName string
}

// ReadDeviceIdentification sends FC 43 (MEI type 14) to read basic device identification.
func (c *Client) ReadDeviceIdentification() (*DeviceIdentification, error) {
	data := []byte{0x0E, 0x01, 0x00}
	respFC, respData, err := c.SendRawPDU(0x2B, data)
	if err != nil {
		return nil, err
	}

	if respFC == 0xAB {
		return nil, fmt.Errorf("device identification not supported")
	}
	if respFC != 0x2B {
		return nil, fmt.Errorf("unexpected function code 0x%02X", respFC)
	}

	if len(respData) < 6 {
		return nil, fmt.Errorf("response too short: %d bytes", len(respData))
	}

	numObjects := int(respData[5])
	id := &DeviceIdentification{}
	pos := 6

	for i := 0; i < numObjects && pos+2 <= len(respData); i++ {
		objID := respData[pos]
		objLen := int(respData[pos+1])
		pos += 2
		if pos+objLen > len(respData) {
			break
		}
		value := strings.TrimRight(string(respData[pos:pos+objLen]), "\x00")
		pos += objLen

		switch objID {
		case 0x00:
			id.VendorName = value
		case 0x01:
			id.ProductCode = value
		case 0x02:
			id.Revision = value
		case 0x03:
			id.VendorURL = value
		case 0x04:
			id.ProductName = value
		case 0x05:
			id.ModelName = value
		case 0x06:
			id.UserAppName = value
		}
	}
	return id, nil
}

// SunSpecInfo holds the result of SunSpec common model discovery.
type SunSpecInfo struct {
	Manufacturer string
	Model        string
	Serial       string
	Version      string
	BaseAddress  uint16
}

var sunSpecBases = []uint16{40000, 50000}

// DiscoverSunSpec probes for SunSpec common model by looking for "SunS" header.
func (c *Client) DiscoverSunSpec() (*SunSpecInfo, error) {
	for _, base := range sunSpecBases {
		info, err := c.trySunSpecBase(base)
		if err != nil {
			continue
		}
		if info != nil {
			return info, nil
		}
	}
	return nil, fmt.Errorf("no SunSpec header found")
}

func (c *Client) trySunSpecBase(base uint16) (*SunSpecInfo, error) {
	data, err := c.ReadHoldingRegisters(base, 2)
	if err != nil {
		return nil, err
	}
	regs := BytesToRegisters(data)
	if len(regs) < 2 || regs[0] != 0x5375 || regs[1] != 0x6E53 {
		return nil, nil
	}

	headerData, err := c.ReadHoldingRegisters(base+2, 2)
	if err != nil {
		return nil, err
	}
	headerRegs := BytesToRegisters(headerData)
	if len(headerRegs) < 2 {
		return nil, nil
	}

	modelID := headerRegs[0]
	modelLen := headerRegs[1]

	if modelID != 1 {
		return nil, fmt.Errorf("first model is %d, not Common Model (1)", modelID)
	}
	if modelLen < 64 {
		return nil, fmt.Errorf("common model length %d too short", modelLen)
	}

	readLen := uint16(64)
	if modelLen < readLen {
		readLen = modelLen
	}
	modelData, err := c.ReadHoldingRegisters(base+4, readLen)
	if err != nil {
		return nil, err
	}
	modelRegs := BytesToRegisters(modelData)
	if len(modelRegs) < int(readLen) {
		return nil, fmt.Errorf("short read: got %d, want %d", len(modelRegs), readLen)
	}

	info := &SunSpecInfo{BaseAddress: base}
	if len(modelRegs) >= 16 {
		info.Manufacturer = strings.TrimRight(DecodeString(modelRegs[0:16]), " \x00")
	}
	if len(modelRegs) >= 32 {
		info.Model = strings.TrimRight(DecodeString(modelRegs[16:32]), " \x00")
	}
	if len(modelRegs) >= 48 {
		info.Version = strings.TrimRight(DecodeString(modelRegs[40:48]), " \x00")
	}
	if len(modelRegs) >= 64 {
		info.Serial = strings.TrimRight(DecodeString(modelRegs[48:64]), " \x00")
	}

	if info.Manufacturer == "" && info.Model == "" && info.Serial == "" {
		return nil, nil
	}
	return info, nil
}
