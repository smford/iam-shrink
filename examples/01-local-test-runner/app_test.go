package main

import (
	"testing"
)

func TestFetchReport(t *testing.T) {
	err := FetchReport("test-report-42")
	if err != nil {
		t.Fatalf("FetchReport failed: %v", err)
	}
}
