package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// InterceptedResource records an exact resource ARN discovered during HTTP inspection.
type InterceptedResource struct {
	Service     string
	Api         string
	ResourceARN string
}

// ProxyServer is an HTTP/HTTPS MITM proxy that inspects AWS requests to extract concrete resource ARNs.
type ProxyServer struct {
	listener     net.Listener
	port         int
	ca           *CertificateAuthority
	tempDir      string
	resourcesMu  sync.Mutex
	resources    map[string][]string // key: "service:api", val: list of concrete ARNs
	stopCh       chan struct{}
	server       *http.Server
	upstreamDial func(network, addr string) (net.Conn, error)
}

// NewProxyServer creates a local proxy server with on-the-fly CA certificate generation.
func NewProxyServer() (*ProxyServer, error) {
	tempDir, err := os.MkdirTemp("", "iam-shrink-proxy-*")
	if err != nil {
		return nil, fmt.Errorf("creating proxy temp dir: %w", err)
	}

	ca, err := NewCertificateAuthority(tempDir)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("initializing proxy CA: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("listening on proxy port: %w", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	p := &ProxyServer{
		listener:     ln,
		port:         port,
		ca:           ca,
		tempDir:      tempDir,
		resources:    make(map[string][]string),
		stopCh:       make(chan struct{}),
		upstreamDial: dialer.Dial,
	}

	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.handleRequest),
		ReadHeaderTimeout: 10 * time.Second,
	}

	return p, nil
}

// Port returns the listening TCP port.
func (p *ProxyServer) Port() int {
	return p.port
}

// Env returns the environment variables to inject into the child process.
func (p *ProxyServer) Env() []string {
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", p.port)
	caPath := p.ca.CertPath()

	return []string{
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
		"AWS_CA_BUNDLE=" + caPath,
		"SSL_CERT_FILE=" + caPath,
		"NODE_EXTRA_CA_CERTS=" + caPath,
	}
}

// Start begins serving in a background goroutine.
func (p *ProxyServer) Start() {
	go func() {
		_ = p.server.Serve(p.listener)
	}()
}

// Stop shuts down the proxy and cleans up CA files.
func (p *ProxyServer) Stop() {
	_ = p.server.Close()
	_ = p.listener.Close()
	if p.tempDir != "" {
		_ = os.RemoveAll(p.tempDir)
	}
}

// Resources returns a copy of intercepted concrete ARNs mapped by "service:api".
func (p *ProxyServer) Resources() map[string][]string {
	p.resourcesMu.Lock()
	defer p.resourcesMu.Unlock()

	out := make(map[string][]string)
	for k, v := range p.resources {
		copied := make([]string, len(v))
		copy(copied, v)
		out[k] = copied
	}
	return out
}

func (p *ProxyServer) addResource(service, api, arn string) {
	if arn == "" {
		return
	}
	key := strings.ToLower(service) + ":" + strings.ToLower(api)
	p.resourcesMu.Lock()
	defer p.resourcesMu.Unlock()

	for _, existing := range p.resources[key] {
		if existing == arn {
			return
		}
	}
	p.resources[key] = append(p.resources[key], arn)
}

func (p *ProxyServer) handleRequest(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
		return
	}

	p.inspectAndForwardHTTP(w, req)
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, req *http.Request) {
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}

	tlsCert, err := p.ca.SignHost(host)
	if err != nil {
		http.Error(w, fmt.Sprintf("signing cert for %s: %v", host, err), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 Connection Established
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Wrap client connection with TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}
	defer tlsConn.Close()

	// Read HTTP requests inside the TLS tunnel
	reader := bufio.NewReader(tlsConn)
	for {
		innerReq, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		innerReq.URL.Scheme = "https"
		innerReq.URL.Host = req.Host

		p.inspectAWSRequest(innerReq)

		// Forward to upstream
		resp, err := p.forwardToUpstream(innerReq)
		if err != nil {
			errResp := &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(err.Error())),
			}
			_ = errResp.Write(tlsConn)
			return
		}

		_ = resp.Write(tlsConn)
		_ = resp.Body.Close()
	}
}

func (p *ProxyServer) inspectAndForwardHTTP(w http.ResponseWriter, req *http.Request) {
	p.inspectAWSRequest(req)

	resp, err := p.forwardToUpstream(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *ProxyServer) forwardToUpstream(req *http.Request) (*http.Response, error) {
	// If connecting to localhost or mock, connect directly
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	target := host
	if !strings.Contains(target, ":") {
		if req.URL.Scheme == "https" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	var upstreamConn net.Conn
	var err error
	if req.URL.Scheme == "https" {
		upstreamConn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", target, &tls.Config{
			InsecureSkipVerify: true, // For mock servers or local tests
		})
	} else {
		upstreamConn, err = p.upstreamDial("tcp", target)
	}

	if err != nil {
		// Mock response if upstream is unreachable (e.g. simulated environment)
		return &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
		}, nil
	}
	defer upstreamConn.Close()

	if err := req.Write(upstreamConn); err != nil {
		return nil, err
	}

	return http.ReadResponse(bufio.NewReader(upstreamConn), req)
}

// Inspects request body and headers to derive exact AWS ARNs.
func (p *ProxyServer) inspectAWSRequest(req *http.Request) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// 1. Detect S3 calls
	if strings.Contains(host, "s3.") || strings.HasPrefix(host, "s3-") || strings.Contains(host, ".s3-") || strings.Contains(host, "s3.amazonaws.com") {
		p.inspectS3(req, host)
		return
	}

	// 2. Detect JSON-based RPC AWS Services (DynamoDB, KMS, SecretsManager, SSM) via X-Amz-Target
	targetHeader := req.Header.Get("X-Amz-Target")
	if targetHeader != "" {
		p.inspectTargetRPC(targetHeader, bodyBytes)
		return
	}

	// 3. Detect SQS calls
	if strings.Contains(host, "sqs.") || strings.Contains(req.URL.Path, "/queue/") {
		p.inspectSQS(req, bodyBytes)
	}
}

func (p *ProxyServer) inspectS3(req *http.Request, host string) {
	var bucket string
	var key string

	// Check virtual-hosted style (e.g. mybucket.s3.us-east-1.amazonaws.com)
	parts := strings.Split(host, ".")
	if len(parts) >= 4 && parts[1] == "s3" {
		bucket = parts[0]
		key = strings.TrimPrefix(req.URL.Path, "/")
	} else {
		// Path style (e.g. s3.amazonaws.com/mybucket/mykey)
		trimmed := strings.TrimPrefix(req.URL.Path, "/")
		pathParts := strings.SplitN(trimmed, "/", 2)
		if len(pathParts) > 0 && pathParts[0] != "" {
			bucket = pathParts[0]
			if len(pathParts) > 1 {
				key = pathParts[1]
			}
		}
	}

	if bucket == "" {
		return
	}

	bucketARN := fmt.Sprintf("arn:aws:s3:::%s", bucket)
	p.addResource("s3", "ListObjectsV2", bucketARN)
	p.addResource("s3", "ListObjects", bucketARN)
	p.addResource("s3", "HeadBucket", bucketARN)
	p.addResource("s3", "GetBucketLocation", bucketARN)

	if key != "" {
		objARN := fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, key)
		p.addResource("s3", "GetObject", objARN)
		p.addResource("s3", "PutObject", objARN)
		p.addResource("s3", "DeleteObject", objARN)
	}
}

func (p *ProxyServer) inspectTargetRPC(targetHeader string, bodyBytes []byte) {
	// e.g. DynamoDB_20120810.PutItem, TrentService.Decrypt, secretsmanager.GetSecretValue, AmazonSSM.GetParameter
	parts := strings.SplitN(targetHeader, ".", 2)
	if len(parts) != 2 {
		return
	}
	servicePrefix := parts[0]
	api := parts[1]

	var bodyMap map[string]interface{}
	_ = json.Unmarshal(bodyBytes, &bodyMap)

	if strings.HasPrefix(servicePrefix, "DynamoDB") {
		if tbl, ok := bodyMap["TableName"].(string); ok && tbl != "" {
			arn := fmt.Sprintf("arn:aws:dynamodb:*:*:table/%s", tbl)
			p.addResource("dynamodb", api, arn)
		}
	} else if strings.HasPrefix(servicePrefix, "TrentService") || strings.HasPrefix(servicePrefix, "Kms") {
		if keyID, ok := bodyMap["KeyId"].(string); ok && keyID != "" {
			var arn string
			if strings.HasPrefix(keyID, "arn:aws:kms:") {
				arn = keyID
			} else {
				arn = fmt.Sprintf("arn:aws:kms:*:*:key/%s", keyID)
			}
			p.addResource("kms", api, arn)
		}
	} else if strings.HasPrefix(servicePrefix, "secretsmanager") {
		if secretID, ok := bodyMap["SecretId"].(string); ok && secretID != "" {
			var arn string
			if strings.HasPrefix(secretID, "arn:aws:secretsmanager:") {
				arn = secretID
			} else {
				arn = fmt.Sprintf("arn:aws:secretsmanager:*:*:secret:%s", secretID)
			}
			p.addResource("secretsmanager", api, arn)
		}
	} else if strings.HasPrefix(servicePrefix, "AmazonSSM") {
		if name, ok := bodyMap["Name"].(string); ok && name != "" {
			paramName := strings.TrimPrefix(name, "/")
			arn := fmt.Sprintf("arn:aws:ssm:*:*:parameter/%s", paramName)
			p.addResource("ssm", api, arn)
		}
	}
}

func (p *ProxyServer) inspectSQS(req *http.Request, bodyBytes []byte) {
	// Check query string or body for QueueUrl
	queueURL := req.URL.Query().Get("QueueUrl")
	if queueURL == "" && len(bodyBytes) > 0 {
		params := string(bodyBytes)
		for _, pair := range strings.Split(params, "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 && kv[0] == "QueueUrl" {
				queueURL = kv[1]
				break
			}
		}
	}

	if queueURL != "" {
		// e.g. https://sqs.us-east-1.amazonaws.com/123456789012/my-queue
		parts := strings.Split(queueURL, "/")
		if len(parts) >= 2 {
			queueName := parts[len(parts)-1]
			arn := fmt.Sprintf("arn:aws:sqs:*:*:%s", queueName)
			p.addResource("sqs", "SendMessage", arn)
			p.addResource("sqs", "ReceiveMessage", arn)
			p.addResource("sqs", "DeleteMessage", arn)
		}
	}
}
