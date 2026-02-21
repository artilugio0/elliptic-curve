package main

import (
	"fmt"
	"io"
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
			publicKey, err := parsePublicKey(cmd)
			if err != nil {
				return err
			}

			sig, err := parseSignature(cmd, args[0])
			if err != nil {
				return err
			}

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
			privateKey, err := parsePrivateKey(cmd)
			if err != nil {
				return err
			}

			msg, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}

			var sig becc.Signature

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
