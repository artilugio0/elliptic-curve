package main

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/artilugio0/becc"
	"github.com/spf13/cobra"
)

func ecdsaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ecdsa",
		Short: "Elliptic curve digital signature algorithm",
		Args:  cobra.NoArgs,
	}

	verifyCmd := &cobra.Command{
		Use:   "verify sig",
		Short: "Verify a signature using ECDSA reading the message from stdin",
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

			publicKeyHex := cmd.Flags().Lookup("public-key").Value.String()
			if publicKeyHex == "" {
				return errors.New("public key not specified")
			}

			if len(publicKeyHex) != 130 || publicKeyHex[:2] != "04" {
				return errors.New("invalid public key format")
			}

			x, ok := new(big.Int).SetString(publicKeyHex[2:66], 16)
			if !ok {
				return errors.New("invalid public key format: invalid x coordinate")
			}

			y, ok := new(big.Int).SetString(publicKeyHex[66:], 16)
			if !ok {
				return errors.New("invalid public key format: invalid y coordinate")
			}

			publicKey := ecc.NewPublicKeyXY(x, y)

			sigHex := args[0]
			r, ok := new(big.Int).SetString(sigHex[:64], 16)
			if !ok {
				return fmt.Errorf("invalid signature format: r value")
			}

			s, ok := new(big.Int).SetString(sigHex[64:], 16)
			if !ok {
				return fmt.Errorf("invalid signature format: r value")
			}

			sig := becc.NewSignature(r, s)

			msg, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}

			verifyOk := publicKey.Verify(becc.SHA256, msg, sig)
			if verifyOk {
				fmt.Println("valid signature")
			} else {
				fmt.Println("invalid signature")
				os.Exit(1)
			}

			return nil
		},
	}

	var signDeterministic bool
	var signLowS bool
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a message from stdin using ECDSA",
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

			msg, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}

			var sig becc.Signature

			fmt.Println(signLowS)
			if signDeterministic {
				sig, err = privateKey.SignDeterministic(becc.SHA256, msg, signLowS)
			} else {
				sig, err = privateKey.Sign(becc.SHA256, msg, signLowS)
			}

			if err != nil {
				return err
			}

			fmt.Printf("%064x%064x\n", sig.R(), sig.S())

			return nil
		},
	}

	signCmd.Flags().BoolVarP(&signDeterministic, "deterministic", "d", true, "Use deterministic signature (RFC 6979)")
	signCmd.Flags().BoolVarP(&signLowS, "low-s", "l", true, "Use low s value in signature")

	cmd.AddCommand(verifyCmd)
	cmd.AddCommand(signCmd)

	return cmd
}
