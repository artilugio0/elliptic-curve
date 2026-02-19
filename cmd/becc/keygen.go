package main

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/artilugio0/becc"
	"github.com/spf13/cobra"
)

func key() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Elliptic curve key operations",
	}

	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a new elliptic curve key pair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			curve := cmd.Flags().Lookup("curve").Value.String()
			var ecc *becc.ECC
			switch curve {
			case "secp256k1":
				ecc = becc.Secp256k1ECC()
			default:
				return fmt.Errorf("invalid curve %q – supported values: secp256k1", curve)
			}

			privateKey, publicKey, err := ecc.GenKeyPair()
			if err != nil {
				return err
			}

			fmt.Printf("private key: %064x\n", privateKey.Int())
			fmt.Printf("public key: 04%064x%064x\n", publicKey.X(), publicKey.Y())

			return nil
		},
	}

	publicCmd := &cobra.Command{
		Use:   "public",
		Short: "Get the public key of a private key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			curve := cmd.Flags().Lookup("curve").Value.String()
			var ecc *becc.ECC
			switch curve {
			case "secp256k1":
				ecc = becc.Secp256k1ECC()
			default:
				return fmt.Errorf("invalid curve %q – supported values: secp256k1", curve)
			}

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
			publicKey := privateKey.PublicKey()

			fmt.Printf("04%064x%064x\n", publicKey.X(), publicKey.Y())

			return nil
		},
	}

	cmd.AddCommand(genCmd)
	cmd.AddCommand(publicCmd)

	return cmd
}
