package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"

	"github.com/pkg/errors"
)

var (
	oidRsaOverPKCS7EnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidAES256CBC                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type Content struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type Recipient struct {
	Version int
	Issuer  struct {
		Name         asn1.RawValue
		SerialNumber *big.Int
	}
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type EncryptedContent struct {
	Type      asn1.ObjectIdentifier
	Algorithm pkix.AlgorithmIdentifier
	Content   asn1.RawValue `asn1:"tag:0,optional"`
}

type EnvelopedData struct {
	Version          int
	Recipients       []Recipient `asn1:"set"`
	EncryptedContent EncryptedContent
}

func ParsePEMFile(filename string) (*EnvelopedData, error) {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read file")
	}

	// Read PEM data
	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil || pemBlock.Type != "PKCS7" {
		return nil, errors.Wrap(err, "Invalid PEM encoded PKCS7 file")
	}

	// Decode ASN.1 content
	var content Content
	_, err = asn1.Unmarshal(pemBlock.Bytes, &content)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode file")
	}

	if !content.Type.Equal(oidRsaOverPKCS7EnvelopedData) {
		return nil, errors.Wrap(err, "Only RSA over PKCS7 EnvelopedData is supported")
	}

	// Decode ASN.1 EnvelopedData
	var envelopedData EnvelopedData
	_, err = asn1.Unmarshal(content.Value.Bytes, &envelopedData)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal EnvelopedData")
	}

	return &envelopedData, nil
}
