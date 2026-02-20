package becc

import (
	"fmt"
	"math/big"
	"testing"
)

func TestModInverse(t *testing.T) {
	tt := []struct {
		n        *big.Int
		m        *big.Int
		expected *big.Int
	}{
		{n: big.NewInt(1), m: big.NewInt(11), expected: big.NewInt(1)},
		{n: big.NewInt(2), m: big.NewInt(11), expected: big.NewInt(6)},
		{n: big.NewInt(3), m: big.NewInt(11), expected: big.NewInt(4)},
		{n: big.NewInt(3), m: big.NewInt(11), expected: big.NewInt(4)},
		{n: big.NewInt(3), m: big.NewInt(7), expected: big.NewInt(5)},
		{n: big.NewInt(5), m: big.NewInt(12), expected: big.NewInt(5)},
		{n: big.NewInt(7), m: big.NewInt(26), expected: big.NewInt(15)},
		{n: big.NewInt(1), m: big.NewInt(10), expected: big.NewInt(1)},
		{n: big.NewInt(2), m: big.NewInt(9), expected: big.NewInt(5)},
		{n: big.NewInt(4), m: big.NewInt(9), expected: big.NewInt(7)},
		{n: big.NewInt(8), m: big.NewInt(21), expected: big.NewInt(8)},
		{n: big.NewInt(17), m: big.NewInt(61), expected: big.NewInt(18)},
		{n: big.NewInt(42), m: big.NewInt(101), expected: big.NewInt(89)},
		{n: big.NewInt(9), m: big.NewInt(100), expected: big.NewInt(89)},
		{n: big.NewInt(89), m: big.NewInt(100), expected: big.NewInt(9)},
		{n: big.NewInt(3), m: big.NewInt(17), expected: big.NewInt(6)},
		{n: big.NewInt(10), m: big.NewInt(17), expected: big.NewInt(12)},
		{n: big.NewInt(1), m: big.NewInt(17), expected: big.NewInt(1)},
		{n: big.NewInt(15), m: big.NewInt(13), expected: big.NewInt(7)},
		{n: big.NewInt(-11), m: big.NewInt(13), expected: big.NewInt(7)},
		{n: big.NewInt(0), m: big.NewInt(17), expected: nil},
		{n: big.NewInt(2), m: big.NewInt(4), expected: nil},
		{n: big.NewInt(6), m: big.NewInt(15), expected: nil},
		{n: big.NewInt(7), m: big.NewInt(21), expected: nil},
	}

	one := big.NewInt(1)
	for _, tc := range tt {
		t.Run(fmt.Sprintf("%d inverse mod %d", tc.n, tc.m), func(t *testing.T) {
			got := modInverse(tc.n, tc.m)
			if got == nil {
				if tc.expected == nil {
					return
				}
				t.Fatalf("got nil, expected: %v", tc.expected)
			}

			if got.Cmp(tc.expected) != 0 {
				t.Errorf("got %d, expected %d", got, tc.expected)
			}

			prod := big.NewInt(0).Mul(tc.n, got)
			prod.Mod(prod, tc.m)
			if prod.Cmp(one) != 0 {
				t.Errorf("%d * %d = %d != 1", tc.n, got, prod)
			}
		})
	}
}

func TestEllipticCurveNewPoint(t *testing.T) {
	ec, _ := NewEllipticCurve(big.NewInt(2), big.NewInt(2), big.NewInt(17))
	tt := []struct {
		x, y *big.Int
		p    Point
	}{
		{x: big.NewInt(10), y: big.NewInt(5), p: ec.NewPoint(big.NewInt(10), big.NewInt(5))},
		{x: big.NewInt(10), y: big.NewInt(19), p: ec.NewPoint(big.NewInt(10), big.NewInt(2))},
		{x: big.NewInt(18), y: big.NewInt(15), p: ec.NewPoint(big.NewInt(1), big.NewInt(15))},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("(%d, %d) (mod 17)", tc.x, tc.y), func(t *testing.T) {
			p := ec.NewPoint(tc.x, tc.y)

			if !p.Eq(tc.p) {
				t.Errorf("got %+v, expected %+v", p, tc.p)
			}
		})
	}
}

func TestInfinity(t *testing.T) {
	ec, _ := NewEllipticCurve(big.NewInt(2), big.NewInt(2), big.NewInt(17))
	if !ec.Infinity().IsInfinity() {
		t.Errorf("expected IsInfinity to be true")
	}
}

func TestPointNeg(t *testing.T) {
	ec, _ := NewEllipticCurve(big.NewInt(2), big.NewInt(2), big.NewInt(17))

	tt := []struct {
		p   Point
		neg Point
	}{
		{
			p:   ec.NewPoint(big.NewInt(10), big.NewInt(5)),
			neg: ec.NewPoint(big.NewInt(10), big.NewInt(12)),
		},
		{
			p:   ec.NewPoint(big.NewInt(1), big.NewInt(16)),
			neg: ec.NewPoint(big.NewInt(1), big.NewInt(1)),
		},
		{
			p:   ec.NewPoint(big.NewInt(3), big.NewInt(1)),
			neg: ec.NewPoint(big.NewInt(3), big.NewInt(16)),
		},
		{
			p:   ec.Infinity(),
			neg: ec.Infinity(),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%+v", tc.p), func(t *testing.T) {
			got := tc.p.Neg()

			if !got.Eq(tc.neg) {
				t.Errorf("got %+v, expected %+v", got, tc.neg)
			}
		})
	}
}

func TestEllipticCurveIsOnCurve(t *testing.T) {
	ec1, _ := NewEllipticCurve(big.NewInt(2), big.NewInt(2), big.NewInt(17))

	tt := []struct {
		ec       EllipticCurve
		p        Point
		expected bool
	}{
		{ec: ec1, p: ec1.NewPoint(big.NewInt(0), big.NewInt(6)), expected: true},
		{ec: ec1, p: ec1.NewPoint(big.NewInt(3), big.NewInt(1)), expected: true},
		{ec: ec1, p: ec1.NewPoint(big.NewInt(5), big.NewInt(1)), expected: true},
		{ec: ec1, p: ec1.NewPoint(big.NewInt(10), big.NewInt(6)), expected: true},
		{ec: ec1, p: ec1.NewPoint(big.NewInt(1), big.NewInt(2)), expected: false},
		{ec: ec1, p: ec1.Infinity(), expected: true},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%+v", tc.p), func(t *testing.T) {
			got := tc.ec.IsOnCurve(tc.p)

			if got != tc.expected {
				t.Errorf("got %+v, expected %+v", got, tc.expected)
			}
		})
	}
}

func TestPointAdd(t *testing.T) {
	ec, _ := NewEllipticCurve(big.NewInt(1), big.NewInt(6), big.NewInt(11))
	point24 := ec.NewPoint(big.NewInt(2), big.NewInt(4))
	ec2_2_17, _ := NewEllipticCurve(big.NewInt(2), big.NewInt(2), big.NewInt(17))

	tt := []struct {
		p1       Point
		p2       Point
		expected Point
	}{
		{p1: ec.Infinity(), p2: ec.Infinity(), expected: ec.Infinity()},
		{p1: ec.Infinity(), p2: point24, expected: point24},
		{p1: point24, p2: ec.Infinity(), expected: point24},
		{p1: point24, p2: ec.NewPoint(big.NewInt(3), big.NewInt(5)), expected: ec.NewPoint(big.NewInt(7), big.NewInt(2))},
		{p1: point24, p2: ec.NewPoint(big.NewInt(2), big.NewInt(7)), expected: ec.Infinity()},

		{p1: point24, p2: ec.NewPoint(big.NewInt(3), big.NewInt(6)), expected: ec.NewPoint(big.NewInt(10), big.NewInt(2))},
		{p1: point24, p2: ec.NewPoint(big.NewInt(2), big.NewInt(4)), expected: ec.NewPoint(big.NewInt(5), big.NewInt(9))},
		{p1: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(6)), p2: ec2_2_17.NewPoint(big.NewInt(3), big.NewInt(1)), expected: ec2_2_17.NewPoint(big.NewInt(13), big.NewInt(10))},
		{p1: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(6)), p2: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(6)), expected: ec2_2_17.NewPoint(big.NewInt(9), big.NewInt(1))},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%+v + %v", tc.p1, tc.p2), func(t *testing.T) {
			got := tc.p1.Add(tc.p2)

			if !got.Eq(tc.expected) {
				t.Errorf("got %+v, expected %+v", got, tc.expected)
			}

			if !tc.p1.ec.IsOnCurve(got) {
				t.Errorf("the result (%+v) is not on curve", got)
			}
		})
	}
}

func TestPointScalarMul(t *testing.T) {
	ec, _ := NewEllipticCurve(big.NewInt(1), big.NewInt(6), big.NewInt(11))
	ec2_2_17, _ := NewEllipticCurve(big.NewInt(2), big.NewInt(2), big.NewInt(17))

	tt := []struct {
		p        Point
		k        *big.Int
		expected Point
	}{
		{p: ec.Infinity(), k: big.NewInt(100), expected: ec.Infinity()},
		{p: ec.Infinity(), k: big.NewInt(0), expected: ec.Infinity()},
		{p: ec.NewPoint(big.NewInt(2), big.NewInt(4)), k: big.NewInt(0), expected: ec.Infinity()},
		{p: ec.NewPoint(big.NewInt(2), big.NewInt(4)), k: big.NewInt(2), expected: ec.NewPoint(big.NewInt(5), big.NewInt(9))},
		{p: ec.NewPoint(big.NewInt(2), big.NewInt(4)), k: big.NewInt(3), expected: ec.NewPoint(big.NewInt(8), big.NewInt(8))},
		{p: ec.NewPoint(big.NewInt(2), big.NewInt(4)), k: big.NewInt(4), expected: ec.NewPoint(big.NewInt(10), big.NewInt(9))},
		{p: ec.NewPoint(big.NewInt(2), big.NewInt(4)), k: big.NewInt(-1), expected: ec.NewPoint(big.NewInt(2), big.NewInt(7))},
		{p: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(6)), k: big.NewInt(2), expected: ec2_2_17.NewPoint(big.NewInt(9), big.NewInt(1))},
		{p: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(6)), k: big.NewInt(3), expected: ec2_2_17.NewPoint(big.NewInt(6), big.NewInt(3))},
		{p: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(6)), k: big.NewInt(4), expected: ec2_2_17.NewPoint(big.NewInt(7), big.NewInt(6))},
		{p: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(6)), k: big.NewInt(-1), expected: ec2_2_17.NewPoint(big.NewInt(0), big.NewInt(11))},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%d * %+v", tc.k, tc.p), func(t *testing.T) {
			got := tc.p.ScalarMul(tc.k)

			if !got.Eq(tc.expected) {
				t.Errorf("got %+v, expected %+v", got, tc.expected)
			}

			if !tc.p.ec.IsOnCurve(got) {
				t.Errorf("the result (%+v) is not on curve", got)
			}
		})
	}
}

func TestEllipticCurveY(t *testing.T) {
	ec1, _ := NewEllipticCurve(big.NewInt(2), big.NewInt(0), big.NewInt(17))

	tt := []struct {
		ec       EllipticCurve
		x        *big.Int
		expected []*big.Int
	}{
		{ec: ec1, x: big.NewInt(0), expected: []*big.Int{big.NewInt(0)}},
		{ec: ec1, x: big.NewInt(1), expected: []*big.Int{}},
		{ec: ec1, x: big.NewInt(2), expected: []*big.Int{}},
		{ec: ec1, x: big.NewInt(3), expected: []*big.Int{big.NewInt(4), big.NewInt(13)}},
		{ec: ec1, x: big.NewInt(4), expected: []*big.Int{big.NewInt(2), big.NewInt(15)}},
		{ec: ec1, x: big.NewInt(5), expected: []*big.Int{big.NewInt(4), big.NewInt(13)}},
		{ec: ec1, x: big.NewInt(6), expected: []*big.Int{}},
		{ec: ec1, x: big.NewInt(7), expected: []*big.Int{big.NewInt(0)}},
		{ec: ec1, x: big.NewInt(8), expected: []*big.Int{big.NewInt(1), big.NewInt(16)}},
		{ec: ec1, x: big.NewInt(9), expected: []*big.Int{big.NewInt(4), big.NewInt(13)}},
		{ec: ec1, x: big.NewInt(10), expected: []*big.Int{big.NewInt(0)}},
		{ec: ec1, x: big.NewInt(11), expected: []*big.Int{}},
		{ec: ec1, x: big.NewInt(12), expected: []*big.Int{big.NewInt(1), big.NewInt(16)}},
		{ec: ec1, x: big.NewInt(13), expected: []*big.Int{big.NewInt(8), big.NewInt(9)}},
		{ec: ec1, x: big.NewInt(14), expected: []*big.Int{big.NewInt(1), big.NewInt(16)}},
		{ec: ec1, x: big.NewInt(15), expected: []*big.Int{}},
		{ec: ec1, x: big.NewInt(16), expected: []*big.Int{}},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%+v", tc.x), func(t *testing.T) {
			got := tc.ec.Y(tc.x)

			if len(got) != len(tc.expected) {
				t.Fatalf("got %+v, expected %+v", got, tc.expected)
			}

			for i, y := range got {
				if tc.expected[i].Cmp(y) != 0 {
					t.Errorf("got %+v, expected %+v", got, tc.expected)
					return
				}
			}
		})
	}
}
