package csm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Event represents a decoded AWS Client-Side Monitoring (CSM) event.
type Event struct {
	Type                string `json:"Type"`
	Service             string `json:"Service"`
	Api                 string `json:"Api"`
	Region              string `json:"Region,omitempty"`
	AccountId           string `json:"AccountId,omitempty"`
	HttpStatusCode      int    `json:"HttpStatusCode,omitempty"`
	FinalHttpStatusCode int    `json:"FinalHttpStatusCode,omitempty"`
	AwsException        string `json:"AwsException,omitempty"`
	FinalAwsException   string `json:"FinalAwsException,omitempty"`
	Timestamp           int64  `json:"Timestamp,omitempty"`
}

// StatusCode returns the effective HTTP response status code.
func (e Event) StatusCode() int {
	if e.FinalHttpStatusCode != 0 {
		return e.FinalHttpStatusCode
	}
	return e.HttpStatusCode
}

// IsFailed returns true if the call resulted in an HTTP error or AWS exception.
func (e Event) IsFailed() bool {
	code := e.StatusCode()
	if code >= 400 {
		return true
	}
	if e.AwsException != "" || e.FinalAwsException != "" {
		return true
	}
	return false
}

// Collector listens on a UDP socket for incoming AWS CSM packets.
type Collector struct {
	conn       *net.UDPConn
	port       int
	eventsMu   sync.Mutex
	events     []Event
	stopCh     chan struct{}
	drainDone  chan struct{}
	running    bool
	wg         sync.WaitGroup
}

// NewCollector creates and binds a UDP listener on 127.0.0.1:<random_port>.
func NewCollector() (*Collector, error) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("binding CSM UDP listener: %w", err)
	}

	// Try increasing socket buffer size to avoid packet drops
	_ = conn.SetReadBuffer(1024 * 1024)

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return &Collector{
		conn:      conn,
		port:      localAddr.Port,
		stopCh:    make(chan struct{}),
		drainDone: make(chan struct{}),
	}, nil
}

// Port returns the UDP port on which the collector is listening.
func (c *Collector) Port() int {
	return c.port
}

// Start begins receiving UDP datagrams in a background goroutine.
func (c *Collector) Start() {
	c.running = true
	c.wg.Add(1)
	go c.listenLoop()
}

func (c *Collector) listenLoop() {
	defer c.wg.Done()

	buf := make([]byte, 65535)
	for {
		// Set a short read deadline so we periodically check stopCh
		_ = c.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-c.stopCh:
					return
				default:
					continue
				}
			}
			select {
			case <-c.stopCh:
				return
			default:
				// other socket error
				continue
			}
		}

		if n > 0 {
			c.parsePacket(buf[:n])
		}
	}
}

func (c *Collector) parsePacket(data []byte) {
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var evt Event
		if err := dec.Decode(&evt); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// Malformed or trailing bytes, stop parsing this packet
			break
		}

		if evt.Service != "" && evt.Api != "" {
			c.eventsMu.Lock()
			c.events = append(c.events, evt)
			c.eventsMu.Unlock()
		}
	}
}

// StopAndDrain waits for drainDuration (e.g. 200ms) to catch trailing packets, then closes the listener.
func (c *Collector) StopAndDrain(drainDuration time.Duration) {
	if !c.running {
		return
	}

	// Allow trailing packets to arrive
	time.Sleep(drainDuration)

	// Signal listen loop to stop
	close(c.stopCh)
	_ = c.conn.Close()
	c.wg.Wait()
	c.running = false
}

// Events returns a copy of all collected CSM events.
func (c *Collector) Events() []Event {
	c.eventsMu.Lock()
	defer c.eventsMu.Unlock()

	res := make([]Event, len(c.events))
	copy(res, c.events)
	return res
}
