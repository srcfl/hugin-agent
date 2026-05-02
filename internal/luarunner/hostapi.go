// Standard host API (forty-two-watts v2.1) — same surface drivers see
// when running inside forty-two-watts itself, so a driver written
// here runs unchanged in 42w (and vice versa).
//
// Surface:
//   host.log(level, msg)          — level ∈ "debug"|"info"|"warn"|"error"
//   host.millis()                 — ms since runtime start
//   host.set_make(brand)          — identity: manufacturer
//   host.set_sn(serial)           — identity: device serial number
//   host.emit(kind, tbl)          — kind ∈ "pv"|"battery"|"meter"|"ev"
//   host.emit_metric(name, value) — long-format scalar time-series metric
package luarunner

import (
	"log"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// EmitFunc is the callback signature for host.emit().
type EmitFunc func(derType string, data map[string]float64)

// MetricFunc is the callback signature for host.emit_metric(). nil = no-op.
type MetricFunc func(name string, value float64)

// LogFunc is the callback signature for host.log(level, msg). nil = log.Printf.
type LogFunc func(level, msg string)

var processStart = time.Now()

// RegisterStandardHostAPI registers the standard host functions on the runtime.
// metricFn may be nil — host.emit_metric becomes a no-op in that case.
func RegisterStandardHostAPI(rt *Runtime, emitFn EmitFunc, logFn LogFunc, metricFn MetricFunc) {
	rt.SetUserData("emit_fn", emitFn)
	if logFn != nil {
		rt.SetUserData("log_fn", logFn)
	}
	if metricFn != nil {
		rt.SetUserData("metric_fn", metricFn)
	}

	rt.RegisterHostFunc("log", makeHostLog(rt))
	rt.RegisterHostFunc("millis", hostMillis)
	rt.RegisterHostFunc("emit", makeHostEmit(rt))
	rt.RegisterHostFunc("emit_metric", makeHostEmitMetric(rt))
	rt.RegisterHostFunc("set_make", makeSetMake(rt))
	rt.RegisterHostFunc("set_sn", makeSetSN(rt))
}

func makeSetMake(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		rt.SetUserData("driver_make", L.CheckString(1))
		return 0
	}
}

func makeSetSN(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		rt.SetUserData("driver_sn", L.CheckString(1))
		return 0
	}
}

func makeHostLog(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		level := L.CheckString(1)
		msg := L.CheckString(2)
		if logRaw, ok := rt.GetUserData("log_fn"); ok {
			if logFn, ok := logRaw.(LogFunc); ok {
				logFn(level, msg)
				return 0
			}
		}
		log.Printf("[lua:%s] %s", level, msg)
		return 0
	}
}

func hostMillis(L *lua.LState) int {
	L.Push(lua.LNumber(time.Since(processStart).Milliseconds()))
	return 1
}

func makeHostEmit(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		kind := L.CheckString(1)
		tbl := L.CheckTable(2)

		data := make(map[string]float64)
		tbl.ForEach(func(key, value lua.LValue) {
			k, ok := key.(lua.LString)
			if !ok {
				return
			}
			if v, ok := value.(lua.LNumber); ok {
				data[string(k)] = float64(v)
			}
		})

		emitRaw, ok := rt.GetUserData("emit_fn")
		if !ok {
			L.Push(lua.LFalse)
			return 1
		}
		emitFn, ok := emitRaw.(EmitFunc)
		if !ok {
			L.Push(lua.LFalse)
			return 1
		}

		emitFn(kind, data)
		L.Push(lua.LTrue)
		return 1
	}
}

func makeHostEmitMetric(rt *Runtime) lua.LGFunction {
	return func(L *lua.LState) int {
		name := L.CheckString(1)
		val := float64(L.CheckNumber(2))
		if metricRaw, ok := rt.GetUserData("metric_fn"); ok {
			if metricFn, ok := metricRaw.(MetricFunc); ok {
				metricFn(name, val)
			}
		}
		return 0
	}
}
