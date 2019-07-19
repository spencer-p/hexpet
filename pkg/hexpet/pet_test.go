package hexpet_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/spencer-p/hexpet/pkg/hexpet"
)

var (
	// TODO(spencer-p) The key can be pre-generated to speed up the test.
	key = RSAKeyMust(rsa.GenerateKey(rand.Reader, 2048))
)

func RSAKeyMust(key *rsa.PrivateKey, err error) *rsa.PrivateKey {
	if err != nil {
		panic(err)
	}
	return key
}

func TestPetSigning(t *testing.T) {

	pet, err := hexpet.GeneratePet(key)
	if err != nil {
		t.Error("Failed to generate a pet")
	}

	t.Logf("Generated pet with id 0x%04X\n", pet.ID)

	if pet.Signature == nil {
		t.Error("Pet is missing a signature (field is nil)")
	}

	if err := pet.Verify(&key.PublicKey); err != nil {
		t.Error("Newly created pet is not verified but should be")
	}

	// Deliberately destroy the key
	e := key.PublicKey.E
	key.PublicKey.E = 6
	defer func() {
		key.PublicKey.E = e
	}()
	if err := pet.Verify(&key.PublicKey); err == nil {
		t.Error("Pet was verified after destroying the public key; should be not verified")
	}
}

func ExampleGenerate() {
	for i := 0; i < 10; i++ {
		pet, err := hexpet.GeneratePet(key)
		if err != nil {
			fmt.Println("Failed to generate pet:", err)
			break
		}
		fmt.Printf("New pet: 0x%04X\n", pet.ID)
	}
}
