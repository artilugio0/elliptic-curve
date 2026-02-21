package main

import (
	"os"

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
			remotePubKey, err := parsePublicKeyString(cmd, args[0])
			if err != nil {
				return err
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
		Use:   "decrypt",
		Short: "Hybrid decryption using elliptic curve + AES-GSM reading the input from stdin",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			privateKey, err := parsePrivateKey(cmd)
			if err != nil {
				return err
			}

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
