package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

type csmEvent struct {
	Version             int    `json:"Version"`
	ClientId            string `json:"ClientId"`
	Type                string `json:"Type"`
	Service             string `json:"Service"`
	Api                 string `json:"Api"`
	Timestamp           int64  `json:"Timestamp"`
	Region              string `json:"Region"`
	HttpStatusCode      int    `json:"HttpStatusCode,omitempty"`
	FinalHttpStatusCode int    `json:"FinalHttpStatusCode,omitempty"`
	AwsException        string `json:"AwsException,omitempty"`
	FinalAwsException   string `json:"FinalAwsException,omitempty"`
}

func main() {
	portStr := os.Getenv("AWS_CSM_PORT")
	if portStr == "" {
		fmt.Fprintf(os.Stderr, "AWS_CSM_PORT not set\n")
		os.Exit(1)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid AWS_CSM_PORT: %s\n", portStr)
		os.Exit(1)
	}

	host := os.Getenv("AWS_CSM_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	destAddr := &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}

	conn, err := net.DialUDP("udp", nil, destAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DialUDP failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	now := time.Now().UnixMilli()

	events := []csmEvent{
		{
			Version:        1,
			Type:           "ApiCall",
			Service:        "S3",
			Api:            "ListObjectsV2",
			Timestamp:      now,
			Region:         "us-east-1",
			HttpStatusCode: 200,
		},
		{
			Version:        1,
			Type:           "ApiCallAttempt",
			Service:        "DynamoDB",
			Api:            "PutItem",
			Timestamp:      now + 10,
			Region:         "us-east-1",
			HttpStatusCode: 200,
		},
		{
			Version:             1,
			Type:                "ApiCallAttempt",
			Service:             "KMS",
			Api:                 "Decrypt",
			Timestamp:           now + 20,
			Region:              "us-east-1",
			FinalHttpStatusCode: 403,
			AwsException:        "AccessDeniedException",
		},
	}

	for _, evt := range events {
		data, err := json.Marshal(evt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Marshal error: %v\n", err)
			continue
		}
		if _, err := conn.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "UDP write error: %v\n", err)
		}
		// Brief pause to simulate network spacing
		time.Sleep(10 * time.Millisecond)
	}

	// Print message to stdout to verify clean forwarding
	fmt.Println("Mock AWS application execution completed successfully.")
}
