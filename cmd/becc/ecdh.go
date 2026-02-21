package main

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

func ecdhCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ecdh remote-pub-key",
		Short: "Elliptic curve Diffie-Hellman algorithm",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			remotePubKey, err := parsePublicKeyString(cmd, args[0])
			if err != nil {
				return err
			}

			privateKey, err := parsePrivateKey(cmd)
			if err != nil {
				return err
			}

			ecdhBytes := privateKey.ECDH(remotePubKey)

			fmt.Println(hex.EncodeToString(ecdhBytes))

			return nil
		},
	}

	return cmd
}
