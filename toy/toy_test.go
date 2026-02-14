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

func TestNewPoint(t *testing.T) {
	tt := []struct {
		x, y, m int64
		p       Point
	}{
		{x: 10, y: 5, m: 15, p: Point{x: 10, y: 5, m: 15}},
		{x: 10, y: 5, m: 9, p: Point{x: 1, y: 5, m: 9}},
		{x: 10, y: 15, m: 7, p: Point{x: 3, y: 1, m: 7}},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("(%d, %d) (mod %d)", tc.x, tc.y, tc.m), func(t *testing.T) {
			p := NewPoint(tc.x, tc.y, tc.m)

			if p != tc.p {
				t.Errorf("got %+v, expected %+v", p, tc.p)
			}
		})
	}
}

func TestInfinity(t *testing.T) {
	if !Infinity().IsInfinity() {
		t.Errorf("expected IsInfinity to be true")
	}
}

func TestPointNeg(t *testing.T) {
	tt := []struct {
		p   Point
		neg Point
	}{
		{p: Point{x: 10, y: 5, m: 15}, neg: Point{x: 10, y: 10, m: 15}},
		{p: Point{x: 1, y: 5, m: 9}, neg: Point{x: 1, y: 4, m: 9}},
		{p: Point{x: 3, y: 1, m: 7}, neg: Point{x: 3, y: 6, m: 7}},
		{p: Point{inf: true}, neg: Point{inf: true}},
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
