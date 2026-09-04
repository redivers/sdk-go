package rediver_test

import (
	"testing"

	rediver "github.com/redivers/sdk-go"
)

func TestPtr_Int(t *testing.T) {
	p := rediver.Ptr(42)
	if *p != 42 {
		t.Errorf("expected 42, got %d", *p)
	}
}

func TestPtr_String(t *testing.T) {
	p := rediver.Ptr("hello")
	if *p != "hello" {
		t.Errorf("expected 'hello', got %q", *p)
	}
}

func TestPtr_Bool(t *testing.T) {
	p := rediver.Ptr(true)
	if !*p {
		t.Error("expected true")
	}
	p2 := rediver.Ptr(false)
	if *p2 {
		t.Error("expected false")
	}
}

func TestPtr_Float64(t *testing.T) {
	p := rediver.Ptr(3.14)
	if *p != 3.14 {
		t.Errorf("expected 3.14, got %f", *p)
	}
}

func TestPtr_ZeroValues(t *testing.T) {
	// Explicit zero values still need a non-nil pointer.
	pi := rediver.Ptr(0)
	if *pi != 0 {
		t.Errorf("expected 0, got %d", *pi)
	}
	ps := rediver.Ptr("")
	if *ps != "" {
		t.Errorf("expected empty string, got %q", *ps)
	}
	pb := rediver.Ptr(false)
	if *pb != false {
		t.Error("expected false")
	}
}

func TestPtr_Struct(t *testing.T) {
	type point struct{ X, Y int }
	p := rediver.Ptr(point{X: 1, Y: 2})
	if p.X != 1 || p.Y != 2 {
		t.Errorf("expected {1,2}, got %v", *p)
	}
}

func TestPtr_ReturnsDistinctPointers(t *testing.T) {
	a := rediver.Ptr(10)
	b := rediver.Ptr(10)
	if a == b {
		t.Error("Ptr should return distinct pointers for each call")
	}
}
