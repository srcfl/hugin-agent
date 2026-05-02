// Package luarunner provides a sandboxed Lua 5.1 VM for executing
// forty-two-watts-style Lua device drivers. The VM has no `os`, `io`,
// or `debug` libraries; `dofile`/`loadfile`/`load`/`require` are
// stripped. Drivers communicate with the Go side only through the
// `host` table — modbus reads, MQTT subscribes, HTTP gets, plus
// emit/log/metric callbacks.
package luarunner

import (
	"fmt"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// Runtime manages a sandboxed Lua VM for driver execution.
type Runtime struct {
	mu sync.Mutex
	L  *lua.LState

	hostFuncs map[string]lua.LGFunction

	udMu     sync.RWMutex
	userData map[string]interface{}
}

// New creates a new Lua runtime with sandbox restrictions.
func New() *Runtime {
	return &Runtime{
		hostFuncs: make(map[string]lua.LGFunction),
		userData:  make(map[string]interface{}),
	}
}

// Init creates the Lua VM and applies sandbox restrictions.
func (r *Runtime) Init() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.L != nil {
		return nil
	}

	L := lua.NewState(lua.Options{
		CallStackSize:       64,
		RegistrySize:        256,
		RegistryMaxSize:     4096,
		SkipOpenLibs:        true,
		IncludeGoStackTrace: true,
	})

	for _, pair := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.LoadLibName, lua.OpenPackage},
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
		{lua.CoroutineLibName, lua.OpenCoroutine},
	} {
		L.Push(L.NewFunction(pair.fn))
		L.Push(lua.LString(pair.name))
		L.Call(1, 0)
	}

	for _, name := range []string{
		"dofile", "loadfile", "load", "require",
		"collectgarbage", "rawget", "rawset", "rawequal",
	} {
		L.SetGlobal(name, lua.LNil)
	}

	L.SetGlobal("io", lua.LNil)
	L.SetGlobal("os", lua.LNil)
	L.SetGlobal("debug", lua.LNil)

	hostTable := L.NewTable()
	for name, fn := range r.hostFuncs {
		hostTable.RawSetString(name, L.NewFunction(fn))
	}
	L.SetGlobal("host", hostTable)

	r.L = L
	return nil
}

// Close shuts down the Lua VM.
func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.L != nil {
		r.L.Close()
		r.L = nil
	}
}

// RegisterHostFunc registers a Go function callable from Lua as host.<name>.
func (r *Runtime) RegisterHostFunc(name string, fn lua.LGFunction) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.hostFuncs[name] = fn

	if r.L != nil {
		host := r.L.GetGlobal("host")
		if tbl, ok := host.(*lua.LTable); ok {
			tbl.RawSetString(name, r.L.NewFunction(fn))
		}
	}
}

// SetUserData stores context data accessible from host functions.
func (r *Runtime) SetUserData(key string, value interface{}) {
	r.udMu.Lock()
	defer r.udMu.Unlock()
	r.userData[key] = value
}

// GetUserData retrieves stored context data.
func (r *Runtime) GetUserData(key string) (interface{}, bool) {
	r.udMu.RLock()
	defer r.udMu.RUnlock()
	v, ok := r.userData[key]
	return v, ok
}

// DoString executes a Lua script string.
func (r *Runtime) DoString(script string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.L == nil {
		return fmt.Errorf("lua runtime not initialized")
	}
	return r.L.DoString(script)
}

// CallGlobal calls a global Lua function by name with the given arguments.
func (r *Runtime) CallGlobal(name string, args ...lua.LValue) (lua.LValue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.L == nil {
		return lua.LNil, fmt.Errorf("lua runtime not initialized")
	}

	fn := r.L.GetGlobal(name)
	if fn == lua.LNil {
		return lua.LNil, fmt.Errorf("function %q not defined", name)
	}

	if err := r.L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, args...); err != nil {
		return lua.LNil, err
	}

	ret := r.L.Get(-1)
	r.L.Pop(1)
	return ret, nil
}

// State returns the raw Lua state. Caller must hold the lock via Lock/Unlock.
func (r *Runtime) State() *lua.LState {
	return r.L
}

// Lock acquires the runtime mutex.
func (r *Runtime) Lock() {
	r.mu.Lock()
}

// Unlock releases the runtime mutex.
func (r *Runtime) Unlock() {
	r.mu.Unlock()
}
