package modbus

import (
	"fmt"
	"math"
)

// DataType represents the type of a Modbus register
type DataType int

const (
	U16 DataType = iota
	I16
	U32
	I32
	F32 // IEEE 754 single-precision float
	STR // Multi-word ASCII string
	U64 // Unsigned 64-bit integer (4 words)
)

func (d DataType) String() string {
	return [...]string{"U16", "I16", "U32", "I32", "F32", "STR", "U64"}[d]
}

// ParseDataType converts a string to DataType.
// Accepts both upper-case ("U16", "I32_BE") and the protocol-style
// lower-case ("u16", "i32_be", "f32_le"). The "_be" / "_le" suffix is
// purely informational on data types that take an Endianness argument
// — callers should pass the endianness separately via DecodeRawValue.
func ParseDataType(s string) (DataType, error) {
	switch s {
	case "U16", "u16":
		return U16, nil
	case "I16", "i16":
		return I16, nil
	case "U32", "u32", "u32_be", "u32_le", "U32_BE", "U32_LE":
		return U32, nil
	case "I32", "i32", "i32_be", "i32_le", "I32_BE", "I32_LE":
		return I32, nil
	case "F32", "f32", "f32_be", "f32_le", "F32_BE", "F32_LE":
		return F32, nil
	case "STR", "str":
		return STR, nil
	case "U64", "u64":
		return U64, nil
	default:
		return 0, fmt.Errorf("unknown data type: %s", s)
	}
}

// WordCount returns the number of Modbus registers needed for a data type.
func (d DataType) WordCount() int {
	switch d {
	case U16, I16:
		return 1
	case U32, I32, F32:
		return 2
	case U64:
		return 4
	default:
		return 1
	}
}

// Endianness for multi-word registers.
type Endianness int

const (
	Big Endianness = iota
	Little
)

func (e Endianness) String() string {
	return [...]string{"BIG", "LITTLE"}[e]
}

// EndiannessFromKind picks Big/Little from a "kind" string like "i32_le".
// Defaults to Big for anything that doesn't end in _le.
func EndiannessFromKind(kind string) Endianness {
	if len(kind) >= 3 && kind[len(kind)-3:] == "_le" {
		return Little
	}
	if len(kind) >= 3 && kind[len(kind)-3:] == "_LE" {
		return Little
	}
	return Big
}

// DecodeRawValue decodes register words without applying any scale factor.
// Use this when you only know the data type + endianness (no driver context).
func DecodeRawValue(registers []uint16, dataType DataType, endian Endianness) (float64, error) {
	if len(registers) < dataType.WordCount() {
		return 0, fmt.Errorf("expected %d registers, got %d", dataType.WordCount(), len(registers))
	}

	switch dataType {
	case U16:
		return float64(registers[0]), nil
	case I16:
		return float64(int16(registers[0])), nil
	case U32:
		return float64(decodeU32(registers, endian)), nil
	case I32:
		return float64(int32(decodeU32(registers, endian))), nil
	case F32:
		bits := decodeU32(registers, endian)
		return float64(math.Float32frombits(bits)), nil
	case U64:
		return float64(decodeU64(registers, endian)), nil
	case STR:
		return 0, fmt.Errorf("use DecodeString for STR registers")
	}
	return 0, fmt.Errorf("unknown data type")
}

func decodeU32(registers []uint16, endian Endianness) uint32 {
	if endian == Big {
		return (uint32(registers[0]) << 16) | uint32(registers[1])
	}
	return (uint32(registers[1]) << 16) | uint32(registers[0])
}

func decodeU64(registers []uint16, endian Endianness) uint64 {
	if endian == Big {
		return (uint64(registers[0]) << 48) | (uint64(registers[1]) << 32) | (uint64(registers[2]) << 16) | uint64(registers[3])
	}
	return (uint64(registers[3]) << 48) | (uint64(registers[2]) << 32) | (uint64(registers[1]) << 16) | uint64(registers[0])
}

// DecodeString decodes register words into a string (2 bytes per register, big-endian).
func DecodeString(registers []uint16) string {
	bytes := make([]byte, 0, len(registers)*2)
	for _, reg := range registers {
		bytes = append(bytes, byte(reg>>8), byte(reg&0xFF))
	}
	for i, b := range bytes {
		if b == 0 {
			bytes = bytes[:i]
			break
		}
	}
	return string(bytes)
}

// BytesToRegisters converts a byte slice (from Modbus response) to uint16 registers.
func BytesToRegisters(data []byte) []uint16 {
	count := len(data) / 2
	regs := make([]uint16, count)
	for i := 0; i < count; i++ {
		regs[i] = uint16(data[i*2])<<8 | uint16(data[i*2+1])
	}
	return regs
}
