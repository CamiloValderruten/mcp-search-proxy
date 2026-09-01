package main

import (
	"math"
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
