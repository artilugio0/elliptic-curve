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

func (e *ECC) GenKeyPair() (*big.Int, Point, error) {
	key, err := rand.Int(rand.Reader, e.n)
	if err != nil {
		return nil, Point{}, err
	}

	pubKey := e.PubKey(key)

	return key, pubKey, nil
}

func (e *ECC) PubKey(key *big.Int) Point {
	return e.g.ScalarMul(key)
}

func (e *ECC) Sign(key *big.Int, hf HashFunc, message []byte) (*big.Int, *big.Int, error) {
	hash := hf(message)

	z := new(big.Int).SetBytes(hash[:])
	z.Mod(z, e.n)

	nSub1 := new(big.Int).Sub(e.n, bi1)
	nHalf := new(big.Int).Div(e.n, bi2)

	var rx, s *big.Int
	for {
		k, err := rand.Int(rand.Reader, nSub1)
		if err != nil {
			return nil, nil, err
		}
		k.Add(k, bi1) // ensure k in [1, n-1]

		r := e.g.ScalarMul(k)
		if r.IsInfinity() {
			continue
		}

		if !e.ec.IsOnCurve(r) {
			panic("r not on curve")
		}

		rx = new(big.Int).Mod(r.x.n, e.n)
		if rx.Sign() == 0 {
			continue
		}

		s = new(big.Int).Mul(
			modInverse(k, e.n),
			new(big.Int).Add(z, new(big.Int).Mul(rx, key)),
		)
		s.Mod(s, e.n)
		if s.Sign() == 0 {
			continue
		}

		// low-s normalization
		if s.Cmp(nHalf) > 0 {
			s.Sub(e.n, s)
		}

		return rx, s, nil
	}

}

func (e *ECC) Verify(pubKey Point, hf HashFunc, message []byte, r, s *big.Int) bool {
	if r.Cmp(bi1) < 0 || s.Cmp(bi1) < 0 || r.Cmp(e.n) >= 0 || s.Cmp(e.n) >= 0 {
		return false
	}

	hash := hf(message)

	z := new(big.Int).SetBytes(hash[:])
	z.Mod(z, e.n)

	w := modInverse(s, e.n)
	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, e.n)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, e.n)

	R := e.g.ScalarMul(u1).Add(pubKey.ScalarMul(u2))

	x := new(big.Int).Mod(R.x.n, e.n)
	return x.Cmp(r) == 0
}

type HashFunc = func([]byte) []byte

func SHA256(m []byte) []byte {
	h := sha256.New()
	h.Write(m)
	hash := h.Sum(nil)

	return hash
}

func Secp256k1ECC() *ECC {
	ec, g, n := Secp256k1()

	return &ECC{
		ec: ec,
		g:  g,
		n:  n,
	}
}
