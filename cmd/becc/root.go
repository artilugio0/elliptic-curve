package main

import "github.com/spf13/cobra"

const (
	curveDefault   string = curveSecp256k1
	curveSecp256k1 string = "secp256k1"
)

func beccCmd() *cobra.Command {
	var (
		curve         string
		privateKeyHex string
		publicKeyHex  string
	)

	cmd := &cobra.Command{
		Use:   "becc",
		Short: "Basic Elliptic Curve Cryptography",
		Long:  `Basic elliptic curve cryptography tool that implement the most used cryptographic operations.`,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	cmd.PersistentFlags().StringVarP(&curve, "curve", "c", curveDefault, "Elliptic curve to use")
	cmd.PersistentFlags().StringVarP(&privateKeyHex, "private-key", "k", "", "Private key in hex format")
	cmd.PersistentFlags().StringVarP(&publicKeyHex, "public-key", "p", "", "Public key in hex format")

	cmd.AddCommand(ecdsaCmd())
	cmd.AddCommand(ecdhCmd())

	return cmd
}
