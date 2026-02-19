package main

import (
	"fmt"
	"math/big"

	"github.com/artilugio0/becc"
)

func main() {
	message := []byte("hello")

	ecc := becc.Secp256k1ECC()

	key, pubKey, err := ecc.GenKeyPair()
	if err != nil {
		panic(err)
	}

	sig, err := key.Sign(becc.SHA256, message, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("key: %064x\n", key.Int())
	fmt.Printf("pubKey: 04%064x%064x\n", pubKey.X(), pubKey.Y())
	fmt.Println("Verified ?", pubKey.Verify(becc.SHA256, message, sig))
	fmt.Printf("sig: %064x%064x\n", sig.R(), sig.S())
	fmt.Printf("r: %064x\ns: %064x\n", sig.R(), sig.S())
	fmt.Println("s < nHalf", sig.S().Cmp(new(big.Int).Div(becc.Secp256k1N, big.NewInt(2))) < 0)

	sNeg := new(big.Int).Sub(becc.Secp256k1N, sig.S())
	sigNeg := becc.NewSignature(sig.R(), sNeg)
	fmt.Println("\nMelleable signature:")
	fmt.Printf("sig: %064x%064x\n", sigNeg.R(), sigNeg.S())
	fmt.Printf("r: %064x\ns: %064x\n", sigNeg.R(), sigNeg.S())
	fmt.Println("Verified ?", pubKey.Verify(becc.SHA256, message, sigNeg))
	fmt.Println("s < nHalf", sNeg.Cmp(new(big.Int).Div(becc.Secp256k1N, big.NewInt(2))) < 0)

	fmt.Println("\n\nDeterministic test:")
	detD, _ := new(big.Int).SetString("0a6fb225cf7962e5f1ce83af725fdb62e611f5c5b8126433ee2a457aa2806683", 16)
	detKey := ecc.NewPrivateKey(detD)
	detPubKey := detKey.PublicKey()
	detSig, err := detKey.SignDeterministic(becc.SHA256, message, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("key: %064x\n", detKey.Int())
	fmt.Printf("pubKey: 04%064x%064x\n", detPubKey.X(), detPubKey.Y())
	fmt.Println("Verified ?", detPubKey.Verify(becc.SHA256, message, detSig))
	fmt.Printf("sig: %064x%064x\n", detSig.R(), detSig.S())
	fmt.Printf("r: %064x\ns: %064x\n", detSig.R(), detSig.S())
}
