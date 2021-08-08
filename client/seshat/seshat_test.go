package seshat

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Tests the properties XOR should have.
func Test_XOR(t *testing.T) {
	for i := 0; i < 10; i++ {
		l := 20
		zeros := fillSlice(0, l)

		x := make([]byte, l)
		n, _ := rand.Read(x)
		if n != l {
			t.Fatal("wrong length of random bitstring")
		}

		if r, _ := XOR(x, zeros); string(r) != string(x) {
			t.Fatalf("x xored with 0 should return x: got %s, expected %s",
				hex.EncodeToString(r), hex.EncodeToString(x))
		}

		if r, _ := XOR(x, x); string(r) != string(zeros) {
			t.Fatalf("x xored with x should return 0: got %s, expected %s",
				hex.EncodeToString(r), hex.EncodeToString(zeros))
		}

		y := make([]byte, l)
		n, _ = rand.Read(y)
		if n != l {
			t.Fatal("wrong length of random bitstring")
		}

		xy, _ := XOR(x, y)
		if r, _ := XOR(y, xy); string(r) != string(x) {
			t.Fatalf("y xored with (x XOR y) should return x: got %s, expected %s",
				hex.EncodeToString(r), hex.EncodeToString(x))
		}
	}
}

// Tests the XOR function when it receives two bytestrings of differing lengths.
func Test_XOR_differentLength(t *testing.T) {
	for l := 10; l < 23; l++ {
		x := make([]byte, l)
		n, _ := rand.Read(x)
		if n != len(x) {
			t.Fatal("wrong length of random bitstring")
		}

		y := make([]byte, l+1) // blackjack!
		n, _ = rand.Read(y)
		if n != len(y) {
			t.Fatal("wrong length of random bitstring")
		}

		_, err := XOR(x, y)
		if err == nil {
			t.Fatalf("different length bytestrings should raise an error when xored (len1: %d, len2: %d)", len(x), len(y))
		}
	}
}

// Tests regular function of the MergeChunks() function.
func Test_MergeChunks(t *testing.T) {
	for l := 4; l < 33; l++ {
		// two chunks
		a := fillSlice(1, l)
		b := fillSlice(1, l+1)

		ab := MergeChunks(a, b)
		if len(ab) != (l + (l + 1)) {
			t.Fatalf("length of the slab is not the sum of the lengths of the chunks: expected %d, got %d", 2*l+1, len(ab))
		}

		// three chunks
		a = fillSlice(1, l)
		b = fillSlice(1, l+1)
		c := fillSlice(1, l+3)

		abc := MergeChunks(a, b, c)
		if len(abc) != (l + (l + 1) + (l + 3)) {
			t.Fatalf("length of the slab is not the sum of the lengths of the chunks: expected %d, got %d", 3*l+4, len(abc))
		}

		a = fillSlice(1, l)
		b = fillSlice(1, l+1)
		c = fillSlice(1, l+3)
		d := fillSlice(1, l+4)

		abcd := MergeChunks(a, b, c, d)
		if len(abcd) != (l + (l + 1) + (l + 3) + (l + 4)) {
			t.Fatalf("length of the slab is not the sum of the lengths of the chunks: expected %d, got %d", 4*l+8, len(abcd))
		}
	}
}

// Utility function.
func fillSlice(value byte, n int) []byte {
	slice := make([]byte, n)
	for i := 0; i < n; i++ {
		slice[i] = value
	}
	return slice
}
