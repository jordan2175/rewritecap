package main

import (
	"testing"
)

func TestAreByteSlicesEqual(t *testing.T) {
	b1 := []byte{10, 20, 30, 40, 50, 60}
	b2 := []byte{10, 20, 30, 40, 50, 60}
	b3 := []byte{10, 20, 35, 40, 50, 60}
	b4 := []byte{10, 20, 30, 40, 50, 60, 70}

	test1a := areByteSlicesEqual(b1, b2)
	if test1a != true {
		t.Error("Test 1a: Expected true, got ", test1a)
	}

	test1b := areByteSlicesEqual(b1, b3)
	if test1b != false {
		t.Error("Test 1b: Expected false, got ", test1b)
	}

	test1c := areByteSlicesEqual(b1, b4)
	if test1c != false {
		t.Error("Test 1c: Expected false, got ", test1c)
	}
}
