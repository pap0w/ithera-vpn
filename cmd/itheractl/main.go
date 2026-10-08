package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pap0w/ithera-vpn/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "genkey":
		priv, err := crypto.GeneratePrivateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(crypto.KeyToBase64(priv))

	case "pubkey":
		fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
		privStr := fs.String("privkey", "", "Base64 private key")
		_ = fs.Parse(os.Args[2:])

		if *privStr == "" {
			fmt.Fprintln(os.Stderr, "Error: -privkey is required")
			os.Exit(1)
		}

		priv, err := crypto.ParseKey(*privStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
			os.Exit(1)
		}

		pub, err := crypto.PublicKey(priv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving public key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(crypto.KeyToBase64(pub))

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: itheractl <command> [options]")
	fmt.Println("Commands:")
	fmt.Println("  genkey              Generate a new Curve25519 private key (Base64)")
	fmt.Println("  pubkey -privkey=KEY Derive the Curve25519 public key from a private key")
}
