package luarunner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// HTTPBridge provides host.http_get and host.http_post to Lua drivers.
type HTTPBridge struct {
	client *http.Client
}

// NewHTTPBridge creates an HTTP bridge with a 5-second timeout.
func NewHTTPBridge() *HTTPBridge {
	return &HTTPBridge{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// RegisterHostFuncs registers HTTP host functions on the runtime.
func (b *HTTPBridge) RegisterHostFuncs(rt *Runtime) {
	rt.RegisterHostFunc("http_get", b.luaHTTPGet)
	rt.RegisterHostFunc("http_post", b.luaHTTPPost)
	rt.RegisterHostFunc("json_decode", luaJSONDecode)
}

func (b *HTTPBridge) luaHTTPGet(L *lua.LState) int {
	url := L.CheckString(1)

	resp, err := b.client.Get(url)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("http_get: %v", err)))
		return 2
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("http_get read: %v", err)))
		return 2
	}

	L.Push(lua.LString(string(body)))
	return 1
}

func (b *HTTPBridge) luaHTTPPost(L *lua.LState) int {
	url := L.CheckString(1)
	payload := L.CheckString(2)
	contentType := L.OptString(3, "application/json")

	resp, err := b.client.Post(url, contentType, strings.NewReader(payload))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("http_post: %v", err)))
		return 2
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("http_post read: %v", err)))
		return 2
	}

	L.Push(lua.LString(string(body)))
	return 1
}
