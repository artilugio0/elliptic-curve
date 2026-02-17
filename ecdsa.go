package becc

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type ECDSA struct {
	ec EllipticCurve
	g  Point
	n  *big.Int
}

func (e *ECDSA) Sign(key *big.Int, message []byte) (*big.Int, *big.Int, error) {
	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)

	z := new(big.Int).SetBytes(hash[:])
	z.Mod(z, e.n)

	var rx, s *big.Int
	for {
		k, err := rand.Int(rand.Reader, e.n)
		if err != nil {
			return nil, nil, err
		}

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

		return rx, s, nil
	}

}

func (e *ECDSA) Verify(message []byte, pubKey Point, r, s *big.Int) bool {
	if r.Cmp(bi1) < 0 || s.Cmp(bi1) < 0 || r.Cmp(e.n) >= 0 || s.Cmp(e.n) >= 0 {
		return false
	}

	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)

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

func Secp256k1ECDSA() *ECDSA {
	ec, g := Secp256k1()

	return &ECDSA{
		ec: ec,
		g:  g,
		n:  Secp256k1N,
	}
}
