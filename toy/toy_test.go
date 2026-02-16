package toy

import (
	"fmt"
	"testing"
)

func TestModInverse(t *testing.T) {
	tt := []struct {
		n   int64
		m   int64
		inv int64
		err error
	}{
		{n: 1, m: 11, inv: 1},
		{n: 2, m: 11, inv: 6},
		{n: 3, m: 11, inv: 4},
		{n: 3, m: 11, inv: 4},
		{n: 3, m: 7, inv: 5},
		{n: 5, m: 12, inv: 5},
		{n: 7, m: 26, inv: 15},
		{n: 1, m: 10, inv: 1},
		{n: 2, m: 9, inv: 5},
		{n: 4, m: 9, inv: 7},
		{n: 8, m: 21, inv: 8},
		{n: 17, m: 61, inv: 18},
		{n: 42, m: 101, inv: 89},
		{n: 9, m: 100, inv: 89},
		{n: 89, m: 100, inv: 9},
		{n: 3, m: 17, inv: 6},
		{n: 10, m: 17, inv: 12},
		{n: 1, m: 17, inv: 1},
		{n: 15, m: 13, inv: 7},
		{n: -11, m: 13, inv: 7},
		{n: 0, m: 17, err: ErrNoInverse},
		{n: 2, m: 4, err: ErrNoInverse},
		{n: 6, m: 15, err: ErrNoInverse},
		{n: 7, m: 21, err: ErrNoInverse},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%d inverse mod %d", tc.n, tc.m), func(t *testing.T) {
			inv, err := modInverse(tc.n, tc.m)
			if err != nil {
				if err == tc.err {
					return
				}
				t.Fatalf("unexpected error: %v", err)
			}

			if inv != tc.inv {
				t.Errorf("got %d, expected %d", inv, tc.inv)
			}

			prod := ((tc.n%tc.m + tc.m) % tc.m) * inv % tc.m
			t.Logf("%d", inv)
			if prod != 1 {
				t.Errorf("%d * %d = %d != 1", tc.n, inv, prod)
			}
		})
	}
}

func TestEllipticCurveNewPoint(t *testing.T) {
	ec, _ := NewEllipticCurve(2, 2, 17)
	tt := []struct {
		x, y int64
		p    Point
	}{
		{x: 10, y: 5, p: Point{x: 10, y: 5, ec: ec}},
		{x: 10, y: 19, p: Point{x: 10, y: 2, ec: ec}},
		{x: 18, y: 15, p: Point{x: 1, y: 15, ec: ec}},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("(%d, %d) (mod 17)", tc.x, tc.y), func(t *testing.T) {
			p := ec.NewPoint(tc.x, tc.y)

			if p != tc.p {
				t.Errorf("got %+v, expected %+v", p, tc.p)
			}
		})
	}
}

func TestInfinity(t *testing.T) {
	ec, _ := NewEllipticCurve(2, 2, 17)
	if !ec.Infinity().IsInfinity() {
		t.Errorf("expected IsInfinity to be true")
	}
}

func TestPointNeg(t *testing.T) {
	ec, _ := NewEllipticCurve(2, 2, 17)

	tt := []struct {
		p   Point
		neg Point
	}{
		{p: Point{x: 10, y: 5, ec: ec}, neg: Point{x: 10, y: 12, ec: ec}},
		{p: Point{x: 1, y: 16, ec: ec}, neg: Point{x: 1, y: 1, ec: ec}},
		{p: Point{x: 3, y: 1, ec: ec}, neg: Point{x: 3, y: 16, ec: ec}},
		{p: Point{inf: true, ec: ec}, neg: Point{inf: true, ec: ec}},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%+v", tc.p), func(t *testing.T) {
			neg := tc.p.Neg()

			if neg != tc.neg {
				t.Errorf("got %+v, expected %+v", neg, tc.neg)
			}
		})
	}
}

func TestPointAdd(t *testing.T) {
	ec, _ := NewEllipticCurve(1, 6, 11)
	ec2_2_17, _ := NewEllipticCurve(2, 2, 17)

	tt := []struct {
		p1       Point
		p2       Point
		expected Point
	}{
		{p1: ec.Infinity(), p2: ec.Infinity(), expected: ec.Infinity()},
		{p1: ec.Infinity(), p2: ec.NewPoint(2, 4), expected: ec.NewPoint(2, 4)},
		{p1: ec.NewPoint(2, 4), p2: ec.Infinity(), expected: ec.NewPoint(2, 4)},
		{p1: ec.NewPoint(2, 4), p2: ec.NewPoint(3, 5), expected: ec.NewPoint(7, 2)},
		{p1: ec.NewPoint(2, 4), p2: ec.NewPoint(2, 7), expected: ec.Infinity()},
		{p1: ec.NewPoint(2, 4), p2: ec.NewPoint(3, 6), expected: ec.NewPoint(10, 2)},
		{p1: ec.NewPoint(2, 4), p2: ec.NewPoint(2, 4), expected: ec.NewPoint(5, 9)},
		{p1: ec2_2_17.NewPoint(0, 6), p2: ec2_2_17.NewPoint(3, 1), expected: ec2_2_17.NewPoint(13, 10)},
		{p1: ec2_2_17.NewPoint(0, 6), p2: ec2_2_17.NewPoint(0, 6), expected: ec2_2_17.NewPoint(9, 1)},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%+v + %v", tc.p1, tc.p2), func(t *testing.T) {
			got := tc.p1.Add(tc.p2)

			if got != tc.expected {
				t.Errorf("got %+v, expected %+v", got, tc.expected)
			}

			if !tc.p1.ec.IsOnCurve(got) {
				t.Errorf("the result (%+v) is not on curve", got)
			}
		})
	}
}

func TestEllipticCurveIsOnCurve(t *testing.T) {
	ec1, _ := NewEllipticCurve(2, 2, 17)

	tt := []struct {
		ec       EllipticCurve
		p        Point
		expected bool
	}{
		{ec: ec1, p: ec1.NewPoint(0, 6), expected: true},
		{ec: ec1, p: ec1.NewPoint(3, 1), expected: true},
		{ec: ec1, p: ec1.NewPoint(5, 1), expected: true},
		{ec: ec1, p: ec1.NewPoint(10, 6), expected: true},
		{ec: ec1, p: ec1.NewPoint(1, 2), expected: false},
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
