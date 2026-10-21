package proxy

import (
	"bytes"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

func TestProxyServerExactResourceExtraction(t *testing.T) {
	p, err := NewProxyServer()
	if err != nil {
		t.Fatalf("NewProxyServer failed: %v", err)
	}
	defer p.Stop()
	p.upstreamDial = func(network, addr string) (net.Conn, error) {
		// Mock offline response
		return nil, net.ErrClosed
	}
	p.Start()

	proxyURL, _ := url.Parse(fmtURL(p.Port()))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// 1. S3 request
	s3Req, _ := http.NewRequest(http.MethodGet, "http://production-assets.s3.us-east-1.amazonaws.com/images/logo.png", nil)
	resp, err := client.Do(s3Req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}

	// 2. DynamoDB PutItem request
	dynamoReq, _ := http.NewRequest(http.MethodPost, "http://dynamodb.us-east-1.amazonaws.com/", bytes.NewReader([]byte(`{"TableName": "users-table-prod"}`)))
	dynamoReq.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
	resp, err = client.Do(dynamoReq)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}

	// 3. KMS Decrypt request
	kmsReq, _ := http.NewRequest(http.MethodPost, "http://kms.us-east-1.amazonaws.com/", bytes.NewReader([]byte(`{"KeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"}`)))
	kmsReq.Header.Set("X-Amz-Target", "TrentService.Decrypt")
	resp, err = client.Do(kmsReq)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}

	res := p.Resources()

	// Check S3
	s3Arns := res["s3:getobject"]
	if len(s3Arns) == 0 || s3Arns[0] != "arn:aws:s3:::production-assets/images/logo.png" {
		t.Errorf("Expected S3 exact object ARN, got: %v", s3Arns)
	}

	// Check DynamoDB
	dynamoArns := res["dynamodb:putitem"]
	if len(dynamoArns) == 0 || dynamoArns[0] != "arn:aws:dynamodb:*:*:table/users-table-prod" {
		t.Errorf("Expected DynamoDB exact table ARN, got: %v", dynamoArns)
	}

	// Check KMS
	kmsArns := res["kms:decrypt"]
	if len(kmsArns) == 0 || kmsArns[0] != "arn:aws:kms:us-east-1:123456789012:key/abcd-1234" {
		t.Errorf("Expected KMS exact key ARN, got: %v", kmsArns)
	}
}

func fmtURL(port int) string {
	return "http://127.0.0.1:" + strconv.Itoa(port)
}
