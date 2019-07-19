package hexpet

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	mrand "math/rand"
	"time"
)

const (
	zipfS = 2   // Power of 2 for distribution
	zipfV = 0xF // First four bits will be fairly random
)

var (
	// Create a RNG with the Zipf distribution. The zipf distribution looks
	// linear on a log-log graph; we want it because it will give us many
	// commodity pets and a small number of rare pets.
	zipf = mrand.NewZipf(mrand.New(mrand.NewSource(time.Now().UnixNano())), zipfS, zipfV, math.MaxUint16)
)

type Pet struct {
	// ID is the hex number that represents this pet
	ID uint16 `json:"id"`

	// Created identifies when this pet was generated
	Created time.Time `json:"created"`

	// Signature is the RSA signature of the above information.  To compute this
	// properly, set Signature = nil and sign the SHA256 hash of the JSON. This
	// behaviour is implemented in Pet.HashedJSON. The signature prevents the
	// saturation of the hex pet market with fakes.
	Signature []byte `json:"signature,omitempty"`
}

// GeneratePet generates a new random pet. The resulting pet will be signed.
func GeneratePet(key *rsa.PrivateKey) (*Pet, error) {
	p := Pet{
		ID:      uint16(zipf.Uint64()),
		Created: time.Now(),
	}

	if err := p.Sign(key); err != nil {
		return nil, err
	}

	return &p, nil
}

// Sign computes the RSA private key signature of your pet.
func (p *Pet) Sign(key *rsa.PrivateKey) error {
	hashed, err := p.HashedJSON()
	if err != nil {
		return err
	}

	sig, err := rsa.SignPKCS1v15(crand.Reader, key, crypto.SHA256, hashed)
	if err != nil {
		return fmt.Errorf("Cannot sign pet: %s", err)
	}

	p.Signature = sig
	return nil
}

// Verify returns an error if the Pet is not valid according to the given public
// key.
func (p *Pet) Verify(pubkey *rsa.PublicKey) error {
	hashed, err := p.HashedJSON()
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashed, p.Signature)
}

// HashedJSON computes the hash of the JSON representation of the Pet for
// cryptographic purposes. It will remove the Signature to compute the hash.
func (p *Pet) HashedJSON() ([]byte, error) {
	// Clear the signature temporarily, guarantee it gets put back
	sig := p.Signature
	p.Signature = nil
	defer func() {
		p.Signature = sig
	}()

	asJson, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("Cannot marshal pet: %s", err)
	}

	hashed := sha256.Sum256(asJson)

	return hashed[:], nil
}
