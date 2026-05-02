package luarunner

import (
	"log"

	lua "github.com/yuin/gopher-lua"

	"github.com/srcfl/hugin-agent/internal/modbus"
)

// ModbusBridge wraps a Modbus client and exposes it to Lua scripts.
type ModbusBridge struct {
	client *modbus.Client
}

// NewModbusBridge creates a bridge from an existing Modbus client.
func NewModbusBridge(client *modbus.Client) *ModbusBridge {
	return &ModbusBridge{client: client}
}

// RegisterHostFuncs adds Modbus host functions to the Lua runtime.
func (b *ModbusBridge) RegisterHostFuncs(rt *Runtime) {
	rt.SetUserData("modbus_bridge", b)

	rt.RegisterHostFunc("modbus_read", makeModbusRead(rt))
	rt.RegisterHostFunc("modbus_write", makeModbusWrite(rt))
	rt.RegisterHostFunc("modbus_write_multiple", makeModbusWriteMultiple(rt))
}

func getBridge(rt *Runtime) *ModbusBridge {
	v, ok := rt.GetUserData("modbus_bridge")
	if !ok {
		return nil
	}
	b, _ := v.(*ModbusBridge)
	return b
}

// host.modbus_read(address, count, "holding"|"input") -> table of uint16
func makeModbusRead(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		addr := uint16(L.CheckNumber(1))
		count := uint16(L.CheckNumber(2))
		kind := L.OptString(3, "holding")

		b := getBridge(rt)
		if b == nil {
			L.Push(lua.LNil)
			L.Push(lua.LString("no modbus client"))
			return 2
		}

		var data []byte
		var err error
		switch kind {
		case "holding":
			data, err = b.client.ReadHoldingRegisters(addr, count)
		case "input":
			data, err = b.client.ReadInputRegisters(addr, count)
		default:
			L.Push(lua.LNil)
			L.Push(lua.LString("invalid register kind: " + kind))
			return 2
		}

		if err != nil {
			log.Printf("[lua:modbus] read %s %d/%d: %v", kind, addr, count, err)
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}

		values := modbus.BytesToRegisters(data)

		tbl := L.NewTable()
		for i, v := range values {
			tbl.RawSetInt(i+1, lua.LNumber(v))
		}
		L.Push(tbl)
		return 1
	}
}

// host.modbus_write(address, value) -> boolean
func makeModbusWrite(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		addr := uint16(L.CheckNumber(1))
		val := uint16(L.CheckNumber(2))

		b := getBridge(rt)
		if b == nil {
			L.Push(lua.LFalse)
			return 1
		}

		if _, err := b.client.WriteSingleRegister(addr, val); err != nil {
			log.Printf("[lua:modbus] write %d=%d: %v", addr, val, err)
			L.Push(lua.LFalse)
			return 1
		}
		L.Push(lua.LTrue)
		return 1
	}
}

// host.modbus_write_multiple(address, {val1, val2, ...}) -> boolean
func makeModbusWriteMultiple(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		addr := uint16(L.CheckNumber(1))
		tbl := L.CheckTable(2)

		b := getBridge(rt)
		if b == nil {
			L.Push(lua.LFalse)
			return 1
		}

		var values []uint16
		tbl.ForEach(func(_, value lua.LValue) {
			if n, ok := value.(lua.LNumber); ok {
				values = append(values, uint16(n))
			}
		})

		if _, err := b.client.WriteMultipleRegisters(addr, values); err != nil {
			log.Printf("[lua:modbus] write_multiple %d/%d: %v", addr, len(values), err)
			L.Push(lua.LFalse)
			return 1
		}
		L.Push(lua.LTrue)
		return 1
	}
}
