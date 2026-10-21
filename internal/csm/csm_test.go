package csm

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCollectorLifecycleAndPacketParsing(t *testing.T) {
	col, err := NewCollector()
	if err != nil {
		t.Fatalf("NewCollector failed: %v", err)
	}
	defer col.StopAndDrain(50 * time.Millisecond)

	port := col.Port()
	if port <= 0 {
		t.Fatalf("Invalid port: %d", port)
	}

	col.Start()

	// Send test UDP packets
	destAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	}

	conn, err := net.DialUDP("udp", nil, destAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer conn.Close()

	evt1 := Event{
		Type:           "ApiCall",
		Service:        "S3",
		Api:            "ListObjectsV2",
		HttpStatusCode: 200,
		Region:         "us-east-1",
	}
	data1, _ := json.Marshal(evt1)
	if _, err := conn.Write(data1); err != nil {
		t.Fatalf("Write evt1 failed: %v", err)
	}

	evt2 := Event{
		Type:                "ApiCallAttempt",
		Service:             "KMS",
		Api:                 "Decrypt",
		FinalHttpStatusCode: 403,
		AwsException:        "AccessDeniedException",
		Region:              "us-west-2",
	}
	data2, _ := json.Marshal(evt2)
	if _, err := conn.Write(data2); err != nil {
		t.Fatalf("Write evt2 failed: %v", err)
	}

	// Give collector a brief moment to process
	time.Sleep(100 * time.Millisecond)

	col.StopAndDrain(100 * time.Millisecond)

	events := col.Events()
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}

	if events[0].Service != "S3" || events[0].Api != "ListObjectsV2" {
		t.Errorf("Unexpected event 0: %+v", events[0])
	}
	if events[0].IsFailed() {
		t.Errorf("Expected event 0 not to be failed")
	}

	if events[1].Service != "KMS" || events[1].Api != "Decrypt" {
		t.Errorf("Unexpected event 1: %+v", events[1])
	}
	if !events[1].IsFailed() {
		t.Errorf("Expected event 1 to be failed (403 AccessDenied)")
	}
}

func TestCollectorMultipleDatagrams(t *testing.T) {
	col, err := NewCollector()
	if err != nil {
		t.Fatalf("NewCollector failed: %v", err)
	}
	col.Start()
	defer col.StopAndDrain(50 * time.Millisecond)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: col.Port(),
	})
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer conn.Close()

	// Send 50 events rapidly
	for i := 0; i < 50; i++ {
		evt := Event{
			Type:           "ApiCall",
			Service:        "DynamoDB",
			Api:            fmt.Sprintf("Method%d", i),
			HttpStatusCode: 200,
		}
		data, _ := json.Marshal(evt)
		_, _ = conn.Write(data)
	}

	time.Sleep(150 * time.Millisecond)
	col.StopAndDrain(100 * time.Millisecond)

	events := col.Events()
	if len(events) < 50 {
		t.Errorf("Expected 50 events, received %d", len(events))
	}
}
