package main

import (
	"fmt"
	"os"
)

func main() {
	cmd := beccCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
