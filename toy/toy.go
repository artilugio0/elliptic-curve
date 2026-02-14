package toy

import "fmt"

func modInverse(n, m int64) (int64, error) {
	var a0, a1 int64 = 0, 1
	var r0, r1 int64 = m, (n%m + m) % m

	for r1 > 1 {
		q := r0 / r1
		a0, a1 = a1, a0-a1*q
		r0, r1 = r1, r0-q*r1
	}

	if r1 == 1 {
		return (a1%m + m) % m, nil
	}

	return 0, ErrNoInverse
}

var ErrNoInverse = fmt.Errorf("gcd(n, m) != 1")

type Point struct {
	x, y, m int64
	inf     bool
}

func NewPoint(x, y, m int64) Point {
	return Point{x: (x%m + m) % m, y: (y%m + m) % m, m: m, inf: false}
}

func Infinity() Point {
	return Point{inf: true}
}

func (p Point) IsInfinity() bool {
	return p.inf
}

func (p Point) Neg() Point {
	if p.inf {
		return Infinity()
	}

	return Point{x: p.x, y: ((-p.y)%p.m + p.m) % p.m, m: p.m, inf: false}
}

func (p Point) String() string {
	if p.inf {
		return "∞"
	}
	return fmt.Sprintf("(%d, %d) mod %d", p.x, p.y, p.m)
}
