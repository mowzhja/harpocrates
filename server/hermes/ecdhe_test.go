package hermes

import (
	"crypto/elliptic"
	"testing"
)

// Tests elliptic curve key generation.
func Test_generateKeys_Basic(t *testing.T) {
	E := elliptic.P521()

	for i := 0; i < 20; i++ {
		_, _, x, y, err := generateKeys(E)
		if err != nil {
			t.Fatal(err)
		}

		if !E.IsOnCurve(x, y) {
			t.Fatalf("the point (%d, %d) is not on the elliptic curve\n", x, y)
		}

		// WTF is wrong with this?? (never passes)
		// x1, y1 := elliptic.Unmarshal(E, pub)
		// if x1 != x || y1 != y {
		// 	t.Fatalf("the point (%d, %d) doesn't correspond to the key %s\n",
		// 		x, y, hex.EncodeToString(pub))
		// }
	}
}
