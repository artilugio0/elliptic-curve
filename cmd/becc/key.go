package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func keyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Elliptic curve key operations",
	}

	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a new elliptic curve key pair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ecc, err := parseCurve(cmd)
			if err != nil {
				return err
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
			privateKey, err := parsePrivateKey(cmd)
			if err != nil {
				return err
			}

			publicKey := privateKey.PublicKey()

			fmt.Printf("04%064x%064x\n", publicKey.X(), publicKey.Y())

			return nil
		},
	}

	cmd.AddCommand(genCmd)
	cmd.AddCommand(publicCmd)

	return cmd
}
