package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/artilugio0/becc"
	"github.com/spf13/cobra"
)

func ecdhCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ecdh remote-pub-key",
		Short: "Elliptic curve Diffie-Hellman algorithm",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			curve := cmd.Flags().Lookup("curve").Value.String()
			var ecc *becc.ECC
			switch curve {
			case "secp256k1":
				ecc = becc.Secp256k1ECC()
			default:
				return fmt.Errorf("invalid curve %q – supported values: secp256k1", curve)
			}

			remotePubKeyHex := args[0]
			if remotePubKeyHex == "" {
				return errors.New("public key not specified")
			}

			if len(remotePubKeyHex) != 130 || remotePubKeyHex[:2] != "04" {
				return errors.New("invalid public key format")
			}

			x, ok := new(big.Int).SetString(remotePubKeyHex[2:66], 16)
			if !ok {
				return errors.New("invalid public key format: invalid x coordinate")
			}

			y, ok := new(big.Int).SetString(remotePubKeyHex[66:], 16)
			if !ok {
				return errors.New("invalid public key format: invalid y coordinate")
			}

			remotePubKey := ecc.NewPublicKeyXY(x, y)

			privateKeyHex := cmd.Flags().Lookup("private-key").Value.String()
			if privateKeyHex == "" {
				return errors.New("private key not specified")
			}

			if len(privateKeyHex) != 64 {
				return errors.New("invalid private key format")
			}

			d, ok := new(big.Int).SetString(privateKeyHex, 16)
			if !ok {
				return errors.New("invalid private key format")
			}

			privateKey := ecc.NewPrivateKey(d)

			ecdhBytes := privateKey.ECDH(remotePubKey)

			fmt.Println(hex.EncodeToString(ecdhBytes))

			return nil
		},
	}

	return cmd
}
