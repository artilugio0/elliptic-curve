package toy

import "fmt"

func modInverse(n, m int64) (int64, error) {
	var a0, a1 int64 = 0, 1
	var r0, r1 int64 = m, modReduce(n, m)

	for r1 > 1 {
		q := r0 / r1
		a0, a1 = a1, a0-a1*q
		r0, r1 = r1, r0-q*r1
	}

	if r1 == 1 {
		return modReduce(a1, m), nil
	}

	return 0, ErrNoInverse
}

func modReduce(n, m int64) int64 {
	return (n%m + m) % m
}

var ErrNoInverse = fmt.Errorf("gcd(n, m) != 1")

type Point struct {
	ec EllipticCurve

	x, y int64
	inf  bool
}

func (p Point) IsInfinity() bool {
	return p.inf
}

func (p Point) Neg() Point {
	if p.inf {
		return Point{ec: p.ec, inf: true}
	}

	return Point{
		ec: p.ec,
		x:  p.x,
		y:  modReduce(-p.y, p.ec.m),
	}
}

func (p Point) Add(q Point) Point {
	if p.IsInfinity() {
		return q
	}

	if q.IsInfinity() {
		return p
	}

	if p.x == q.x && p.y != q.y {
		return p.ec.Infinity()
	}

	var slope int64
	if p.x == q.x && p.y == q.y {
		if p.y == 0 {
			return p.ec.Infinity()
		}

		inv, err := modInverse(2*p.y, p.ec.m)
		if err != nil {
			panic("mod inverse failed")
		}
		x_squared := modReduce(p.x*p.x, p.ec.m)
		x_squared_3 := modReduce(3*x_squared, p.ec.m)
		x_squared_3_a := modReduce(x_squared_3+p.ec.a, p.ec.m)
		slope = modReduce(x_squared_3_a*inv, p.ec.m)
	} else {
		inv, err := modInverse(q.x-p.x, p.ec.m)
		if err != nil {
			panic("mod inverse failed")
		}
		delta_y := modReduce(q.y-p.y, p.ec.m)
		slope = modReduce(delta_y*inv, p.ec.m)
	}

	slope2 := modReduce(slope*slope, p.ec.m)
	slope2_px := modReduce(slope2-p.x, p.ec.m)
	x := modReduce(slope2_px-q.x, p.ec.m)

	px_x := modReduce(p.x-x, p.ec.m)
	slope_px_x := modReduce(slope*px_x, p.ec.m)
	y := modReduce(slope_px_x-p.y, p.ec.m)

	return p.ec.NewPoint(x, y)
}

func (p Point) String() string {
	if p.inf {
		return "∞"
	}
	return fmt.Sprintf("(%d, %d) mod %d", p.x, p.y, p.ec.m)
}

type EllipticCurve struct {
	a, b, m int64
}

func NewEllipticCurve(a, b, m int64) (EllipticCurve, error) {
	a2 := modReduce(a*a, m)
	a2_4 := modReduce(a2*4, m)
	b2 := modReduce(b*b, m)
	b3 := modReduce(b2*b, m)
	b3_27 := modReduce(b3*27, m)

	if modReduce(a2_4+b3_27, m) == 0 {
		return EllipticCurve{}, ErrInvalidParameters
	}

	return EllipticCurve{a: a, b: b, m: m}, nil
}

func (ec EllipticCurve) NewPoint(x, y int64) Point {
	return Point{
		x:  modReduce(x, ec.m),
		y:  modReduce(y, ec.m),
		ec: ec,
	}
}

func (ec EllipticCurve) Infinity() Point {
	return Point{inf: true, ec: ec}
}

func (ec EllipticCurve) IsOnCurve(p Point) bool {
	x2 := modReduce(p.x*p.x, ec.m)
	x3 := modReduce(x2*p.x, ec.m)
	ax := modReduce(ec.a*p.x, ec.m)
	x3_ax := modReduce(x3+ax, ec.m)
	return p.IsInfinity() || modReduce(p.y*p.y, ec.m) == modReduce(x3_ax+ec.b, ec.m)
}

var ErrInvalidParameters error = fmt.Errorf("invalid elliptic curve parameters")
