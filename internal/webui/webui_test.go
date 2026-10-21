package webui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/smford/iam-shrink/internal/render"
)

func TestWebUIServerEndpoints(t *testing.T) {
	items := []render.ActionItem{
		{Action: "s3:GetObject", Service: "s3", ResourceARNs: []string{"arn:aws:s3:::my-bucket/*"}},
		{Action: "dynamodb:PutItem", Service: "dynamodb"},
	}

	srv, err := NewServer(0, items)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Stop()
	srv.Start()

	baseURL := "http://127.0.0.1:" + strconv.Itoa(srv.Port())

	// 1. Test GET /
	resp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "iam-shrink") {
		t.Errorf("Expected HTML title in response")
	}

	// 2. Test GET /api/policy
	resp, err = http.Get(baseURL + "/api/policy")
	if err != nil {
		t.Fatalf("GET /api/policy failed: %v", err)
	}
	defer resp.Body.Close()

	var returnedItems []render.ActionItem
	if err := json.NewDecoder(resp.Body).Decode(&returnedItems); err != nil {
		t.Fatalf("Decoding /api/policy failed: %v", err)
	}
	if len(returnedItems) != 2 {
		t.Errorf("Expected 2 items, got %d", len(returnedItems))
	}

	// 3. Test POST /api/render
	reqBody := []byte(`{"format": "tf", "selected": ["s3:GetObject"]}`)
	resp, err = http.Post(baseURL+"/api/render", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /api/render failed: %v", err)
	}
	defer resp.Body.Close()

	rendered, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(rendered), "s3:GetObject") {
		t.Errorf("Expected rendered policy in response, got:\n%s", string(rendered))
	}
}
