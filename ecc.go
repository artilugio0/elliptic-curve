package becc

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type ECC struct {
	ec EllipticCurve
	g  Point
	n  *big.Int
}

func (e *ECC) NewPrivateKey(d *big.Int) PrivateKey {
	return PrivateKey{
		d:   d,
		ecc: e,
	}
}

func (e *ECC) NewPublicKey(p Point) PublicKey {
	return PublicKey{
		p:   p,
		ecc: e,
	}
}

func (e *ECC) NewPublicKeyXY(x, y *big.Int) PublicKey {
	return PublicKey{
		p:   e.ec.NewPoint(x, y),
		ecc: e,
	}
}

func (e *ECC) GenKeyPair() (PrivateKey, PublicKey, error) {
	d, err := rand.Int(rand.Reader, e.n)
	if err != nil {
		return PrivateKey{}, PublicKey{}, err
	}

	priv := PrivateKey{
		d:   d,
		ecc: e,
	}

	pub := PublicKey{
		p:   e.g.ScalarMul(d),
		ecc: e,
	}

	return priv, pub, nil
}

type HashFunc = func([]byte) []byte

func SHA256(m []byte) []byte {
	h := sha256.Sum256(m)
	return h[:]
}

func Secp256k1ECC() *ECC {
	ec, g, n := Secp256k1()

	return &ECC{
		ec: ec,
		g:  g,
		n:  n,
	}
}

type PrivateKey struct {
	d   *big.Int
	ecc *ECC
}

func (priv PrivateKey) Int() *big.Int {
	return new(big.Int).Set(priv.d)
}

func (priv PrivateKey) Sign(hf HashFunc, message []byte) (Signature, error) {
	hash := hf(message)

	z := new(big.Int).SetBytes(hash[:])
	z.Mod(z, priv.ecc.n)

	nSub1 := new(big.Int).Sub(priv.ecc.n, bi1)
	nHalf := new(big.Int).Div(priv.ecc.n, bi2)

	var rx, s *big.Int
	for {
		k, err := rand.Int(rand.Reader, nSub1)
		if err != nil {
			return Signature{}, err
		}
		k.Add(k, bi1) // ensure k in [1, n-1]

		r := priv.ecc.g.ScalarMul(k)
		if r.IsInfinity() {
			continue
		}

		if !priv.ecc.ec.IsOnCurve(r) {
			panic("r not on curve")
		}

		rx = new(big.Int).Mod(r.x.n, priv.ecc.n)
		if rx.Sign() == 0 {
			continue
		}

		s = new(big.Int).Mul(
			modInverse(k, priv.ecc.n),
			new(big.Int).Add(z, new(big.Int).Mul(rx, priv.d)),
		)
		s.Mod(s, priv.ecc.n)
		if s.Sign() == 0 {
			continue
		}

		// low-s normalization
		if s.Cmp(nHalf) > 0 {
			s.Sub(priv.ecc.n, s)
		}

		return Signature{
			r: rx,
			s: s,
		}, nil
	}
}

func (priv PrivateKey) PublicKey() PublicKey {
	p := priv.ecc.g.ScalarMul(priv.d)

	return PublicKey{
		p:   p,
		ecc: priv.ecc,
	}
}

func (priv PrivateKey) ECDH(pub2 PublicKey) []byte {
	point := pub2.p.ScalarMul(priv.d)
	yEven := new(big.Int).Mod(point.y.n, bi2)

	if yEven.Sign() == 0 {
		return append([]byte{2}, point.x.n.Bytes()...)
	}

	return append([]byte{3}, point.x.n.Bytes()...)
}

type PublicKey struct {
	p   Point
	ecc *ECC
}

func (pub PublicKey) Verify(hf HashFunc, message []byte, sig Signature) bool {
	if sig.r.Cmp(bi1) < 0 || sig.s.Cmp(bi1) < 0 ||
		sig.r.Cmp(pub.ecc.n) >= 0 || sig.s.Cmp(pub.ecc.n) >= 0 {
		return false
	}

	hash := hf(message)

	z := new(big.Int).SetBytes(hash[:])
	z.Mod(z, pub.ecc.n)

	w := modInverse(sig.s, pub.ecc.n)
	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, pub.ecc.n)
	u2 := new(big.Int).Mul(sig.r, w)
	u2.Mod(u2, pub.ecc.n)

	R := pub.ecc.g.ScalarMul(u1).Add(pub.p.ScalarMul(u2))

	x := new(big.Int).Mod(R.x.n, pub.ecc.n)
	return x.Cmp(sig.r) == 0
}

func (pub PublicKey) X() *big.Int {
	return pub.p.X()
}

func (pub PublicKey) Y() *big.Int {
	return pub.p.Y()
}

type Signature struct {
	r *big.Int
	s *big.Int
}

func NewSignature(r, s *big.Int) Signature {
	return Signature{
		r: r,
		s: s,
	}
}

func (sig Signature) R() *big.Int {
	return new(big.Int).Set(sig.r)
}

func (sig Signature) S() *big.Int {
	return new(big.Int).Set(sig.s)
}
