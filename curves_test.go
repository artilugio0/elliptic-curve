package becc

import (
	"fmt"
	"math/big"
	"testing"
)

func Secp256k1Test(t *testing.T) {
	ec, g := Secp256k1()
	tt := []struct {
		p       Point
		belongs bool
	}{
		{p: g, belongs: true},
		{p: g.ScalarMul(big.NewInt(100)), belongs: true},
		{p: g.ScalarMul(big.NewInt(1000)), belongs: true},
		{p: point(t, ec,
			"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		), belongs: true},
		{p: point(t, ec,
			"ed7ffde4cb4fd27164ae5f435e4a3ae1905ba30e9f06eccab50fcbd9f341f81",
			"731e74549045132626c4b20dd9971afffdcf3a400e12b2dd7f887edfb8b205a8",
		), belongs: true},
		{p: point(t, ec,
			"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b6",
		), belongs: false},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%s", tc.p), func(t *testing.T) {
			got := ec.IsOnCurve(tc.p)
			if got != tc.belongs {
				t.Errorf("got %t, expected %t", got, tc.belongs)
			}
		})
	}
}

func point(t *testing.T, ec EllipticCurve, x, y string) Point {
	t.Helper()
	px, ok := new(big.Int).SetString(x, 16)
	if !ok {
		t.Fatalf("invalid coordinate literal: %s", x)
	}

	py, ok := new(big.Int).SetString(y, 16)
	if !ok {
		t.Fatalf("invalid coordinate literal: %s", y)
	}

	return ec.NewPoint(px, py)
}
