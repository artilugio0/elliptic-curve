package becc

import (
	"fmt"
	"math/big"
)

var (
	bi_1 *big.Int = big.NewInt(-1)
	bi0  *big.Int = big.NewInt(0)
	bi1  *big.Int = big.NewInt(1)
	bi2  *big.Int = big.NewInt(2)
	bi3  *big.Int = big.NewInt(3)
	bi4  *big.Int = big.NewInt(4)
	bi27 *big.Int = big.NewInt(27)
)

func modInverse(n, m *big.Int) *big.Int {
	a0, a1 := big.NewInt(0), big.NewInt(1)
	r0, r1 := new(big.Int).Set(m), new(big.Int).Mod(n, m)

	for r1.Cmp(bi1) == 1 {
		q := new(big.Int).Div(r0, r1)

		a1New := new(big.Int).Set(a1)
		a1New.Mul(a1New, q).Sub(a0, a1New)

		r1New := new(big.Int).Set(r1)
		r1New.Mul(r1New, q).Sub(r0, r1New)

		a0, a1 = a1, a1New
		r0, r1 = r1, r1New
	}

	if r1.Cmp(bi1) == 0 {
		return a1.Mod(a1, m)
	}

	return nil
}

type EllipticCurve struct {
	a, b *FieldElement
	m    *big.Int

	n *big.Int
}

var ErrInvalidParameters error = fmt.Errorf("invalid elliptic curve parameters")

func NewEllipticCurve(a, b, m *big.Int) (EllipticCurve, error) {
	fa := NewFieldElement(a, m)
	fb := NewFieldElement(b, m)

	disc := fa.Mul(fa).Mul(NewFieldElement(bi4, m)).
		Add(fb.Mul(fb).Mul(fb).Mul(NewFieldElement(bi27, m)))

	if disc.Eq(NewFieldElement(bi0, m)) {
		return EllipticCurve{}, ErrInvalidParameters
	}

	return EllipticCurve{
		a: fa,
		b: fb,
		m: new(big.Int).Set(m),
	}, nil
}

func (ec EllipticCurve) Infinity() Point {
	return Point{
		inf: true,
		ec:  ec,
		x:   NewFieldElement(bi0, ec.m),
		y:   NewFieldElement(bi0, ec.m),
	}
}

func (ec EllipticCurve) NewPoint(x, y *big.Int) Point {
	return Point{
		x:  NewFieldElement(x, ec.m),
		y:  NewFieldElement(y, ec.m),
		ec: ec,
	}
}

func (ec EllipticCurve) IsOnCurve(p Point) bool {
	if p.IsInfinity() {
		return true
	}

	lhs := p.y.Mul(p.y)

	rhs := p.x.Mul(p.x).Mul(p.x).
		Add(p.x.Mul(ec.a)).
		Add(ec.b)

	return lhs.Eq(rhs)
}

type Point struct {
	ec EllipticCurve

	x, y *FieldElement
	inf  bool
}

func (p Point) String() string {
	if p.inf {
		return "∞"
	}
	return fmt.Sprintf("(0x%064x, 0x%064x)", p.x.n, p.y.n)
}

func (p Point) IsInfinity() bool {
	return p.inf
}

func (p Point) Eq(q Point) bool {
	return p.x.Eq(q.x) && p.y.Eq(q.y)
}

func (p Point) Neg() Point {
	if p.inf {
		return Point{
			ec:  p.ec,
			inf: true,
			x:   &FieldElement{n: big.NewInt(0), m: p.x.m},
			y:   &FieldElement{n: big.NewInt(0), m: p.y.m},
		}
	}

	return Point{
		ec: p.ec,
		x:  &FieldElement{n: new(big.Int).Set(p.x.n), m: p.x.m},
		y:  p.y.Neg(),
	}
}

func (p Point) Add(q Point) Point {
	if p.IsInfinity() {
		return q
	}

	if q.IsInfinity() {
		return p
	}

	if p.x.Eq(q.x) && !p.y.Eq(q.y) {
		return p.ec.Infinity()
	}

	var slope *FieldElement
	if p.x.Eq(q.x) && p.y.Eq(q.y) {
		if p.y.IsZero() {
			return p.ec.Infinity()
		}

		slope = p.x.Mul(p.x).MulInt(3).
			Add(p.ec.a).
			Mul(p.y.MulInt(2).ModInverse())

	} else {
		slope = q.y.Sub(p.y).Mul(q.x.Sub(p.x).ModInverse())
	}

	x := slope.Mul(slope).Sub(p.x).Sub(q.x)
	y := slope.Mul(p.x.Sub(x)).Sub(p.y)

	return Point{
		x:  x,
		y:  y,
		ec: p.ec,
	}
}

/*
func (p Point) ScalarMul(k *big.Int) Point {
	// right to left

	k = new(big.Int).Set(k)
	if k.Cmp(bi0) == -1 {
		p = p.Neg()
		k = k.Mul(k, bi_1)
	}

	result := p.ec.Infinity()
	addend := p
	for i := range k.BitLen() {
		if k.Bit(i) == 1 {
			result = result.Add(addend)
		}

		addend = addend.Add(addend)
	}

	return result
}
*/

func (p Point) ScalarMul(k *big.Int) Point {
	// left to right

	k = new(big.Int).Set(k)
	if k.Cmp(bi0) == -1 {
		p = p.Neg()
		k = k.Mul(k, bi_1)
	}

	result := p.ec.Infinity()
	bitlen := k.BitLen()
	for i := bitlen - 1; i >= 0; i-- {
		result = result.Add(result)

		if k.Bit(i) == 1 {
			result = result.Add(p)
		}
	}

	return result
}

type FieldElement struct {
	m *big.Int
	n *big.Int
}

func (fe *FieldElement) String() string {
	return fmt.Sprintf("%s (mod %s)", fe.n, fe.m)
}

func NewFieldElement(n, m *big.Int) *FieldElement {
	return &FieldElement{
		m: new(big.Int).Set(m),
		n: new(big.Int).Mod(n, m),
	}
}

func NewFieldElementInt(n, m int64) *FieldElement {
	mod := big.NewInt(m)
	num := big.NewInt(n)
	return &FieldElement{
		m: mod,
		n: num.Mod(num, mod),
	}
}

func (fe *FieldElement) Add(n *FieldElement) *FieldElement {
	result := new(big.Int).Add(fe.n, n.n)
	return &FieldElement{
		m: fe.m,
		n: result.Mod(result, fe.m),
	}
}

func (fe *FieldElement) Sub(n *FieldElement) *FieldElement {
	result := new(big.Int).Sub(fe.n, n.n)
	return &FieldElement{
		m: fe.m,
		n: result.Mod(result, fe.m),
	}
}

func (fe *FieldElement) Mul(n *FieldElement) *FieldElement {
	result := new(big.Int).Mul(fe.n, n.n)
	return &FieldElement{
		m: fe.m,
		n: result.Mod(result, fe.m),
	}
}

func (fe *FieldElement) MulInt(n int64) *FieldElement {
	result := big.NewInt(n)
	result.Mul(fe.n, result)

	return &FieldElement{
		m: fe.m,
		n: result.Mod(result, fe.m),
	}
}

func (fe *FieldElement) Neg() *FieldElement {
	neg := new(big.Int).Sub(fe.m, fe.n)
	neg.Mod(neg, fe.m)

	return &FieldElement{
		m: fe.m,
		n: neg,
	}
}

func (fe *FieldElement) ModInverse() *FieldElement {
	inv := modInverse(fe.n, fe.m)
	if inv == nil {
		return nil
	}

	return &FieldElement{
		m: fe.m,
		n: inv,
	}
}

func (fe *FieldElement) Eq(n *FieldElement) bool {
	return fe.n.Cmp(n.n) == 0
}

func (fe *FieldElement) IsZero() bool {
	return fe.n.Cmp(bi0) == 0
}
