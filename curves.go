package becc

import "math/big"

var (
	Secp256k1A    = big.NewInt(0)
	Secp256k1B    = big.NewInt(7)
	Secp256k1P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

	Secp256k1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	Secp256k1Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	Secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	Secp256k1H = big.NewInt(1)
)

func Secp256k1() (EllipticCurve, Point) {
	ec, err := NewEllipticCurve(Secp256k1A, Secp256k1B, Secp256k1P)
	if err != nil {
		panic(err)
	}

	ec.n = Secp256k1N
	g := ec.NewPoint(Secp256k1Gx, Secp256k1Gy)

	return ec, g
}
