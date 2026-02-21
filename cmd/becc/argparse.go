package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/artilugio0/becc"
	"github.com/spf13/cobra"
)

type curveDef struct {
	name string
	ecc  *becc.ECC
	len  int
}

var curves = []curveDef{
	{"secp256k1", becc.Secp256k1ECC(), 32},
	{"secp256r1", becc.Secp256r1ECC(), 32},
	{"secp384r1", becc.Secp384r1ECC(), 48},
	{"secp521r1", becc.Secp521r1ECC(), 66}, // TODO: fix bit count bugs
}

func parseCurve(cmd *cobra.Command) (*becc.ECC, error) {
	curveName := cmd.Flags().Lookup("curve").Value.String()

	def, err := getCurveDef(curveName)
	if err != nil {
		return nil, err
	}

	return def.ecc, nil
}

func getCurveDef(name string) (curveDef, error) {
	i, ok := slices.BinarySearchFunc(curves, name, func(cd curveDef, n string) int {
		if cd.name < n {
			return -1
		} else if cd.name == n {
			return 0
		}
		return 1
	})

	if !ok {
		supportedCurves := make([]string, len(curves))
		for i, c := range curves {
			supportedCurves[i] = c.name
		}
		return curveDef{}, fmt.Errorf("invalid curve %q – supported values: %s", name, strings.Join(supportedCurves, " "))
	}

	return curves[i], nil
}

func parsePrivateKey(cmd *cobra.Command) (becc.PrivateKey, error) {
	curveName := cmd.Flags().Lookup("curve").Value.String()

	def, err := getCurveDef(curveName)
	if err != nil {
		return becc.PrivateKey{}, err
	}

	privateKeyHex := cmd.Flags().Lookup("private-key").Value.String()
	if privateKeyHex == "" {
		return becc.PrivateKey{}, errors.New("private key not specified")
	}

	if len(privateKeyHex) != def.len*2 {
		return becc.PrivateKey{}, errors.New("invalid private key format")
	}

	d, ok := new(big.Int).SetString(privateKeyHex, 16)
	if !ok {
		return becc.PrivateKey{}, errors.New("invalid private key format")
	}

	return def.ecc.NewPrivateKey(d), nil
}

func parsePublicKey(cmd *cobra.Command) (becc.PublicKey, error) {
	publicKeyHex := cmd.Flags().Lookup("public-key").Value.String()
	if publicKeyHex == "" {
		return becc.PublicKey{}, errors.New("public key not specified")
	}

	return parsePublicKeyString(cmd, publicKeyHex)
}

func parsePublicKeyString(cmd *cobra.Command, publicKeyHex string) (becc.PublicKey, error) {
	curveName := cmd.Flags().Lookup("curve").Value.String()

	def, err := getCurveDef(curveName)
	if err != nil {
		return becc.PublicKey{}, err
	}

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return becc.PublicKey{}, errors.New("invalid public key format")
	}

	return def.ecc.NewPublicKeyBytes(publicKeyBytes)
}

func parseSignature(cmd *cobra.Command, sigHex string) (becc.Signature, error) {
	curveName := cmd.Flags().Lookup("curve").Value.String()

	def, err := getCurveDef(curveName)
	if err != nil {
		return becc.Signature{}, err
	}

	if len(sigHex) != def.len*4 {
		return becc.Signature{}, fmt.Errorf("invalid signature format: invalid length")
	}

	r, ok := new(big.Int).SetString(sigHex[:def.len*2], 16)
	if !ok {
		return becc.Signature{}, fmt.Errorf("invalid signature format: r value")
	}

	s, ok := new(big.Int).SetString(sigHex[def.len*2:], 16)
	if !ok {
		return becc.Signature{}, fmt.Errorf("invalid signature format: r value")
	}

	sig := becc.NewSignature(r, s)

	return sig, nil
}
