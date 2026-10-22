package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// CSMEvent mirrors the AWS Client-Side Monitoring (CSM) UDP datagram format
// automatically emitted by official AWS SDKs (Go, Python/Boto3, Node.js, Java).
type CSMEvent struct {
	Version             int    `json:"Version"`
	ClientId            string `json:"ClientId"`
	Type                string `json:"Type"`
	Service             string `json:"Service"`
	Api                 string `json:"Api"`
	Timestamp           int64  `json:"Timestamp"`
	Region              string `json:"Region"`
	HttpStatusCode      int    `json:"HttpStatusCode,omitempty"`
	FinalHttpStatusCode int    `json:"FinalHttpStatusCode,omitempty"`
}

// emitCSM sends a CSM telemetry event to the local loopback UDP port configured by iam-shrink.
func emitCSM(service, api string, statusCode int) error {
	portStr := os.Getenv("AWS_CSM_PORT")
	if portStr == "" {
		// When running outside of iam-shrink, CSM telemetry is simply ignored
		return nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid AWS_CSM_PORT: %w", err)
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
		return fmt.Errorf("dial UDP: %w", err)
	}
	defer conn.Close()

	event := CSMEvent{
		Version:             1,
		Type:                "ApiCall",
		Service:             service,
		Api:                 api,
		Timestamp:           time.Now().UnixMilli(),
		Region:              "us-east-1",
		HttpStatusCode:      statusCode,
		FinalHttpStatusCode: statusCode,
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	_, err = conn.Write(payload)
	return err
}

// FetchReport simulates reading application reports from an S3 bucket and querying DynamoDB.
func FetchReport(reportID string) error {
	// Simulate S3 ListObjectsV2 & GetObject
	if err := emitCSM("S3", "ListObjectsV2", 200); err != nil {
		return err
	}
	if err := emitCSM("S3", "GetObject", 200); err != nil {
		return err
	}

	// Simulate DynamoDB Query
	if err := emitCSM("DynamoDB", "Query", 200); err != nil {
		return err
	}

	// Simulate KMS Decrypt for server-side encrypted assets
	if err := emitCSM("KMS", "Decrypt", 200); err != nil {
		return err
	}

	return nil
}

func main() {
	fmt.Println("Running Sample Microservice...")
	if err := FetchReport("rep-10293"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Sample Microservice executed successfully.")
}
