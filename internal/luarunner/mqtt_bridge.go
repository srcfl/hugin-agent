package luarunner

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	lua "github.com/yuin/gopher-lua"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// MQTTBridge provides host.mqtt_* functions to Lua drivers.
type MQTTBridge struct {
	client mqtt.Client
	mu     sync.Mutex
	msgs   []mqttMsg
}

type mqttMsg struct {
	Topic   string `json:"topic"`
	Payload string `json:"payload"`
}

// NewMQTTBridge creates a bridge connected to the given broker.
func NewMQTTBridge(host string, port int, username, password string) (*MQTTBridge, error) {
	broker := fmt.Sprintf("tcp://%s:%d", host, port)
	clientID := fmt.Sprintf("hugin-agent-%d", time.Now().UnixMilli())

	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID(clientID).
		SetConnectTimeout(5 * time.Second).
		SetAutoReconnect(false)

	if username != "" {
		opts.SetUsername(username)
	}
	if password != "" {
		opts.SetPassword(password)
	}

	b := &MQTTBridge{}

	opts.SetDefaultPublishHandler(func(_ mqtt.Client, msg mqtt.Message) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.msgs = append(b.msgs, mqttMsg{
			Topic:   msg.Topic(),
			Payload: string(msg.Payload()),
		})
	})

	client := mqtt.NewClient(opts)
	token := client.Connect()
	if !token.WaitTimeout(5 * time.Second) {
		return nil, fmt.Errorf("mqtt connect timeout: %s", broker)
	}
	if token.Error() != nil {
		return nil, fmt.Errorf("mqtt connect: %w", token.Error())
	}

	b.client = client
	return b, nil
}

// Close disconnects the MQTT client.
func (b *MQTTBridge) Close() {
	if b.client != nil && b.client.IsConnected() {
		b.client.Disconnect(250)
	}
}

// RegisterHostFuncs registers host.mqtt_subscribe, host.mqtt_messages,
// host.mqtt_publish, and host.json_decode on the runtime.
func (b *MQTTBridge) RegisterHostFuncs(rt *Runtime) {
	rt.RegisterHostFunc("mqtt_subscribe", b.luaSubscribe)
	rt.RegisterHostFunc("mqtt_messages", b.luaMessages)
	rt.RegisterHostFunc("mqtt_publish", b.luaPublish)
	rt.RegisterHostFunc("json_decode", luaJSONDecode)
}

func (b *MQTTBridge) luaSubscribe(L *lua.LState) int {
	topic := L.CheckString(1)
	token := b.client.Subscribe(topic, 0, nil)
	if !token.WaitTimeout(3 * time.Second) || token.Error() != nil {
		log.Printf("[mqtt] subscribe %s failed: %v", topic, token.Error())
		L.Push(lua.LFalse)
		return 1
	}
	log.Printf("[mqtt] subscribed: %s", topic)
	L.Push(lua.LTrue)
	return 1
}

func (b *MQTTBridge) luaMessages(L *lua.LState) int {
	b.mu.Lock()
	msgs := b.msgs
	b.msgs = nil
	b.mu.Unlock()

	tbl := L.NewTable()
	for i, m := range msgs {
		entry := L.NewTable()
		entry.RawSetString("topic", lua.LString(m.Topic))
		entry.RawSetString("payload", lua.LString(m.Payload))
		tbl.RawSetInt(i+1, entry)
	}
	L.Push(tbl)
	return 1
}

func (b *MQTTBridge) luaPublish(L *lua.LState) int {
	topic := L.CheckString(1)
	payload := L.CheckString(2)
	token := b.client.Publish(topic, 0, false, payload)
	if !token.WaitTimeout(3 * time.Second) || token.Error() != nil {
		L.Push(lua.LFalse)
		return 1
	}
	L.Push(lua.LTrue)
	return 1
}

func luaJSONDecode(L *lua.LState) int {
	str := L.CheckString(1)
	var raw interface{}
	if err := json.Unmarshal([]byte(str), &raw); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(goToLua(L, raw))
	return 1
}

// RegisterMQTTStubs registers no-op MQTT host functions for drivers that
// won't be tested against a real broker.
func RegisterMQTTStubs(rt *Runtime) {
	rt.RegisterHostFunc("mqtt_subscribe", func(L *lua.LState) int {
		L.CheckString(1)
		L.Push(lua.LTrue)
		return 1
	})
	rt.RegisterHostFunc("mqtt_messages", func(L *lua.LState) int {
		L.Push(L.NewTable())
		return 1
	})
	rt.RegisterHostFunc("mqtt_publish", func(L *lua.LState) int {
		L.CheckString(1)
		L.CheckString(2)
		L.Push(lua.LTrue)
		return 1
	})
	rt.RegisterHostFunc("json_decode", luaJSONDecode)
}
