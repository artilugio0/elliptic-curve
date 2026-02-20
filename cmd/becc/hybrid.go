package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/artilugio0/becc"
	"github.com/spf13/cobra"
)

func hybridCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hybrid",
		Short: "Hybrid encryption/decryption using elliptic curve + AES-GSM",
		Args:  cobra.NoArgs,
	}

	encryptCmd := &cobra.Command{
		Use:   "encrypt remote-pub-key",
		Short: "Hybrid encryption using elliptic curve + AES-GSM reading the input from stdin",
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
			compressedPubKey, err := hex.DecodeString(remotePubKeyHex)
			if err != nil {
				return fmt.Errorf("invalid remote public key: %v", err)
			}

			remotePubKey, err := ecc.NewPublicKeyCompressed(compressedPubKey)
			if err != nil {
				return fmt.Errorf("invalid remote public: %v", err)
			}

			ciphertext, err := remotePubKey.Encrypt(os.Stdin)
			if err != nil {
				return err
			}

			if _, err := os.Stdout.Write(ciphertext); err != nil {
				return err
			}

			return nil
		},
	}

	decryptCmd := &cobra.Command{
		Use:   "decrypt remote-pub-key",
		Short: "Hybrid decryption using elliptic curve + AES-GSM reading the input from stdin",
		Args:  cobra.ExactArgs(0),
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

			plaintext, err := privateKey.Decrypt(os.Stdin)
			if err != nil {
				return err
			}

			if _, err := os.Stdout.Write(plaintext); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.AddCommand(encryptCmd)
	cmd.AddCommand(decryptCmd)

	return cmd
}
