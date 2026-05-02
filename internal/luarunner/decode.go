// Modbus register decode helpers (forty-two-watts v2.1).
//
// Drivers read raw uint16[] from host.modbus_read and reassemble them
// into larger integers / floats with explicit endianness. The "_le"
// variants take (lo, hi); "_be" variants take (hi, lo). No implicit
// endianness helpers — callers must be explicit.
package luarunner

import (
	"encoding/binary"
	"encoding/json"
	"math"

	lua "github.com/yuin/gopher-lua"
)

// RegisterDecodeHostFuncs adds register decoding helpers to the runtime.
func RegisterDecodeHostFuncs(rt *Runtime) {
	rt.RegisterHostFunc("decode_i16", decodeI16)
	rt.RegisterHostFunc("decode_u32_be", decodeU32BE)
	rt.RegisterHostFunc("decode_u32_le", decodeU32LE)
	rt.RegisterHostFunc("decode_i32_be", decodeI32BE)
	rt.RegisterHostFunc("decode_i32_le", decodeI32LE)
	rt.RegisterHostFunc("decode_f32_be", decodeF32BE)
	rt.RegisterHostFunc("json_decode", jsonDecode)
}

func decodeI16(L *lua.LState) int {
	L.Push(lua.LNumber(int16(uint16(L.CheckNumber(1)))))
	return 1
}

func decodeU32BE(L *lua.LState) int {
	hi := uint32(uint16(L.CheckNumber(1)))
	lo := uint32(uint16(L.CheckNumber(2)))
	L.Push(lua.LNumber(hi<<16 | lo))
	return 1
}

func decodeU32LE(L *lua.LState) int {
	lo := uint32(uint16(L.CheckNumber(1)))
	hi := uint32(uint16(L.CheckNumber(2)))
	L.Push(lua.LNumber(hi<<16 | lo))
	return 1
}

func decodeI32BE(L *lua.LState) int {
	hi := uint32(uint16(L.CheckNumber(1)))
	lo := uint32(uint16(L.CheckNumber(2)))
	L.Push(lua.LNumber(int32(hi<<16 | lo)))
	return 1
}

func decodeI32LE(L *lua.LState) int {
	lo := uint32(uint16(L.CheckNumber(1)))
	hi := uint32(uint16(L.CheckNumber(2)))
	L.Push(lua.LNumber(int32(hi<<16 | lo)))
	return 1
}

func decodeF32BE(L *lua.LState) int {
	hi := uint16(L.CheckNumber(1))
	lo := uint16(L.CheckNumber(2))
	var buf [4]byte
	binary.BigEndian.PutUint16(buf[0:2], hi)
	binary.BigEndian.PutUint16(buf[2:4], lo)
	L.Push(lua.LNumber(math.Float32frombits(binary.BigEndian.Uint32(buf[:]))))
	return 1
}

func jsonDecode(L *lua.LState) int {
	var data interface{}
	if err := json.Unmarshal([]byte(L.CheckString(1)), &data); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(goToLua(L, data))
	return 1
}

func goToLua(L *lua.LState, v interface{}) lua.LValue {
	switch val := v.(type) {
	case nil:
		return lua.LNil
	case bool:
		if val {
			return lua.LTrue
		}
		return lua.LFalse
	case float64:
		return lua.LNumber(val)
	case string:
		return lua.LString(val)
	case []interface{}:
		tbl := L.NewTable()
		for i, item := range val {
			tbl.RawSetInt(i+1, goToLua(L, item))
		}
		return tbl
	case map[string]interface{}:
		tbl := L.NewTable()
		for k, item := range val {
			tbl.RawSetString(k, goToLua(L, item))
		}
		return tbl
	default:
		return lua.LNil
	}
}
