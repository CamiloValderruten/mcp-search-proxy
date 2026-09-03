package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCosineSimilarity(t *testing.T) {
	vecA := []float32{1.0, 0.0, 0.0}
	vecB := []float32{1.0, 0.0, 0.0}
	vecC := []float32{0.0, 1.0, 0.0}

	// Identical vectors should have similarity 1.0
	simIdentical := CosineSimilarity(vecA, vecB)
	if math.Abs(float64(simIdentical-1.0)) > 1e-5 {
		t.Fatalf("expected similarity 1.0, got %f", simIdentical)
	}

	// Orthogonal vectors should have similarity 0.0
	simOrthogonal := CosineSimilarity(vecA, vecC)
	if math.Abs(float64(simOrthogonal-0.0)) > 1e-5 {
		t.Fatalf("expected similarity 0.0, got %f", simOrthogonal)
	}
}

func TestNewEmbedder(t *testing.T) {
	e := NewEmbedder("", "", "")
	if e.model != "text-embedding-3-small" {
		t.Errorf("Expected default model, got %s", e.model)
	}
	if e.url != "https://api.openai.com/v1/embeddings" {
		t.Errorf("Expected default URL, got %s", e.url)
	}

	e2 := NewEmbedder("key", "model-x", "http://x")
	if e2.model != "model-x" {
		t.Errorf("Expected custom model")
	}
	if e2.url != "http://x" {
		t.Errorf("Expected custom url")
	}
	if e2.apiKey != "key" {
		t.Errorf("Expected custom api key")
	}
}

func TestEmbedderEmbed(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		var req openAIEmbeddingRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		
		if len(req.Input) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		
		resp := openAIEmbeddingResponse{
			Data: []openAIEmbeddingData{
				{Index: 0, Embedding: []float32{0.1, 0.2}},
				{Index: 1, Embedding: []float32{0.3, 0.4}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	e := NewEmbedder("test-key", "test-model", mockServer.URL)
	
	// Test empty
	res, err := e.Embed(context.Background(), []string{})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(res) != 0 {
		t.Errorf("Expected empty results")
	}
	
	// Test normal
	res, err = e.Embed(context.Background(), []string{"test1", "test2"})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(res))
	}
	if res[0][0] != 0.1 || res[1][0] != 0.3 {
		t.Errorf("Unexpected embedding values")
	}
	
	// Test error status
	eBadKey := NewEmbedder("bad-key", "test-model", mockServer.URL)
	_, err = eBadKey.Embed(context.Background(), []string{"test1"})
	if err == nil {
		t.Errorf("Expected error for bad auth")
	}
}
