package becc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math"
	"math/big"
	"slices"
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

func (e *ECC) NewPublicKeyCompressed(c []byte) (PublicKey, error) {
	if len(c) != 33 || (c[0] != 2 && c[0] != 3) {
		return PublicKey{}, errors.New("invalid key format")
	}

	x := new(big.Int).SetBytes(c[1:])
	ys := e.ec.Y(x)

	fmt.Printf("ys: %+v\n", ys)

	if len(ys) == 0 {
		return PublicKey{}, errors.New("invalid x value")
	}

	evenY := c[0] == 2
	if len(ys) == 1 {
		if new(big.Int).Mod(ys[0], bi2).Sign() == 0 && !evenY {
			return PublicKey{}, errors.New("invalid y parity")
		}

		return PublicKey{
			p:   e.ec.NewPoint(x, ys[0]),
			ecc: e,
		}, nil
	}

	parity := int(c[0] % 2)
	ys0Parity := new(big.Int).Mod(ys[0], bi2).Sign()
	if ys0Parity == parity {
		return PublicKey{
			p:   e.ec.NewPoint(x, ys[0]),
			ecc: e,
		}, nil
	}

	return PublicKey{
		p:   e.ec.NewPoint(x, ys[1]),
		ecc: e,
	}, nil
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

type HashFunc = func() hash.Hash

var SHA256 = sha256.New

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

func (priv PrivateKey) Sign(hf HashFunc, message []byte, lowS bool) (Signature, error) {
	h := hf()
	h.Write(message)
	hash := h.Sum(nil)

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
		if lowS && s.Cmp(nHalf) > 0 {
			s.Sub(priv.ecc.n, s)
		}

		return Signature{
			r: rx,
			s: s,
		}, nil
	}
}

func (priv PrivateKey) SignDeterministic(hf HashFunc, message []byte, lowS bool) (Signature, error) {
	h := hf()
	h.Write(message)
	hash := h.Sum(nil)

	z := new(big.Int).SetBytes(hash[:])
	z.Mod(z, priv.ecc.n)

	hlen := h.Size()
	qlen := priv.ecc.n.BitLen()
	rlen := int(math.Ceil(float64(qlen) / 8.0))

	dBytes := priv.d.Bytes()
	// pad to rlen
	if len(dBytes) < rlen {
		dBytes = slices.Concat(bytes.Repeat([]byte{0}, rlen-len(dBytes)), dBytes)
	}

	hInt := new(big.Int).SetBytes(hash)
	hInt.Mod(hInt, priv.ecc.n)

	mBytes := hInt.Bytes()
	// pad to rlen
	if len(mBytes) < rlen {
		mBytes = slices.Concat(bytes.Repeat([]byte{0}, rlen-len(mBytes)), mBytes)
	}

	V := bytes.Repeat([]byte{0x01}, hlen)
	K := bytes.Repeat([]byte{0x00}, hlen)

	hm := hmac.New(hf, K)
	hm.Write(slices.Concat(V, []byte{0x00}, dBytes, mBytes))
	K = hm.Sum(nil)

	hm = hmac.New(hf, K)
	hm.Write(V)
	V = hm.Sum(nil)

	hm.Reset()
	hm.Write(slices.Concat(V, []byte{0x01}, dBytes, mBytes))
	K = hm.Sum(nil)

	hm = hmac.New(hf, K)
	hm.Write(V)
	V = hm.Sum(nil)

	var rx, s *big.Int
	var r Point
	var T []byte

	nHalf := new(big.Int).Div(priv.ecc.n, bi2)

	for {
		T = []byte{}

		for len(T) < rlen {
			hm.Reset()
			hm.Write(V)
			V = hm.Sum(nil)
			T = slices.Concat(T, V)
		}
		k := new(big.Int).SetBytes(T[:rlen])

		if k.Cmp(bi1) <= 0 || k.Cmp(priv.ecc.n) >= 0 {
			goto retry
		}

		r = priv.ecc.g.ScalarMul(k)
		if r.IsInfinity() {
			goto retry
		}

		rx = new(big.Int).Mod(r.x.n, priv.ecc.n)
		if rx.Sign() == 0 {
			goto retry
		}

		s = new(big.Int).Mul(
			modInverse(k, priv.ecc.n),
			new(big.Int).Add(z, new(big.Int).Mul(rx, priv.d)),
		)
		s.Mod(s, priv.ecc.n)
		if s.Sign() == 0 {
			goto retry
		}

		// low-s normalization
		if lowS && s.Cmp(nHalf) > 0 {
			s.Sub(priv.ecc.n, s)
		}

		return Signature{
			r: rx,
			s: s,
		}, nil

	retry:
		hm.Reset()
		hm.Write(slices.Concat(V, []byte{0x00}))
		K = hm.Sum(nil)
		hm = hmac.New(hf, K)
		hm.Write(V)
		V = hm.Sum(nil)
		continue
	}

	return Signature{}, nil
}

func (priv PrivateKey) PublicKey() PublicKey {
	p := priv.ecc.g.ScalarMul(priv.d)

	return PublicKey{
		p:   p,
		ecc: priv.ecc,
	}
}

func (priv PrivateKey) ECDH(pub2 PublicKey) []byte {
	sharedPoint := pub2.p.ScalarMul(priv.d)
	sharedKey := priv.ecc.NewPublicKey(sharedPoint)
	return sharedKey.Compressed()
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

	h := hf()
	h.Write(message)
	hash := h.Sum(nil)

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

func (pub PublicKey) Compressed() []byte {
	yParity := new(big.Int).Mod(pub.p.y.n, bi2).Sign()

	bs := pub.p.x.n.Bytes()
	padding := bytes.Repeat([]byte{0x00}, 32-len(bs))
	header := []byte{byte(2 + yParity)}

	return slices.Concat(header, padding, bs)
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
