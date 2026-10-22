package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

type CSMEvent struct {
	Version             int    `json:"Version"`
	Type                string `json:"Type"`
	Service             string `json:"Service"`
	Api                 string `json:"Api"`
	Timestamp           int64  `json:"Timestamp"`
	Region              string `json:"Region"`
	HttpStatusCode      int    `json:"HttpStatusCode,omitempty"`
	FinalHttpStatusCode int    `json:"FinalHttpStatusCode,omitempty"`
}

func emit(service, api string) {
	portStr := os.Getenv("AWS_CSM_PORT")
	if portStr == "" {
		return
	}
	port, _ := strconv.Atoi(portStr)
	dest := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	conn, err := net.DialUDP("udp", nil, dest)
	if err != nil {
		return
	}
	defer conn.Close()

	ev := CSMEvent{
		Version:        1,
		Type:           "ApiCall",
		Service:        service,
		Api:            api,
		Timestamp:      time.Now().UnixMilli(),
		Region:         "us-east-1",
		HttpStatusCode: 200,
	}
	b, _ := json.Marshal(ev)
	_, _ = conn.Write(b)
}

func main() {
	fmt.Println("Simulating application executing AWS operations...")
	emit("S3", "GetObject")
	emit("S3", "PutObject")
	emit("DynamoDB", "PutItem")
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Operations complete.")
}
