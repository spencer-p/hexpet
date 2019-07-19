package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"log"
	"os"
)

var (
	outputfile = flag.String("output", "mykey", "filename to save private and public key")
	bits       = flag.Int("bits", 2048, "number of bits for the key")
)

func dump(b []byte, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Could not open %s to write key: %s\n", filename, err)
	}
	defer f.Close()

	enc := base64.NewEncoder(base64.StdEncoding.WithPadding(base64.StdPadding), f)

	enc.Write(b)
}

func main() {
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		log.Fatal("Could not generate key:", err)
	}

	dump(x509.MarshalPKCS1PrivateKey(key), *outputfile)
	dump(x509.MarshalPKCS1PublicKey(&key.PublicKey), *outputfile+".pub")
}
