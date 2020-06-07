package main

/*
#cgo CFLAGS: -I/usr/local/include/ykpiv/ -Wall
#cgo LDFLAGS: -l ykpiv
#include <stdlib.h>
#include <ykpiv/ykpiv.h>
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "<file>")
		return
	}

	fileName := os.Args[1]
	encryptedPemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.WithError(err).Fatal("Failed to read file")
	}

	// Read PEM data
	pemBlock, _ := pem.Decode(encryptedPemData)
	if pemBlock == nil || pemBlock.Type != "PKCS7" {
		log.Fatal("Invalid PEM encoded PKCS7 file")
	}

	// Decode ASN.1 content
	var content Content
	_, err = asn1.Unmarshal(pemBlock.Bytes, &content)
	if err != nil {
		log.WithError(err).Fatal("Failed to decode file")
	}

	if !content.Type.Equal(oidRsaOverPKCS7EnvelopedData) {
		log.Fatal("Only RSA over PKCS7 EnvelopedData is supported")
	}

	// Decode ASN.1 EnvelopedData
	var envelopedData EnvelopedData
	_, err = asn1.Unmarshal(content.Value.Bytes, &envelopedData)
	if err != nil {
		log.WithError(err).Fatal("Failed to unmarshal EnvelopedData")
	}

	if !envelopedData.EncryptedContent.Algorithm.Algorithm.Equal(oidAES256CBC) {
		log.Fatal("Only AES-256 CBC is supported")
	}

	// TODO
	yk_verbosity := 0
	yk_reader := "Yubikey"
	yk_slot := 0x9a

	// Try to connect to Yubikey
	var state *C.ykpiv_state

	res := C.ykpiv_init(&state, C.int(yk_verbosity))
	if res != C.YKPIV_OK {
		log.Fatal("Failed to initialize yubico library")
	}

	res = C.ykpiv_connect(state, C.CString(yk_reader))
	if res != C.YKPIV_OK {
		log.Fatal("Failed to connect to yubikey.\nTry removing and reconnecting the device.")
	}

	// Read slot certificate
	var certificateLen C.ulong
	var certificatePtr *C.uchar
	res = C.ykpiv_util_read_cert(state, C.uchar(yk_slot), &certificatePtr, &certificateLen)
	if res != C.YKPIV_OK {
		log.Fatalf("Failed to read certificate of slot 0x%x", yk_slot)
	}

	certificateData := C.GoBytes(unsafe.Pointer(certificatePtr), C.int(certificateLen))
	certificate, err := x509.ParseCertificate(certificateData)
	if err != nil {
		log.WithError(err).Fatalf("Failed to parse certificate of slot 0x%x", yk_slot)
	}

	// Find a matching recipient
	var encryptedKey []byte
	for _, v := range envelopedData.Recipients {
		if v.Issuer.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			encryptedKey = v.EncryptedKey
		}
	}
	if encryptedKey == nil {
		log.Fatal("File can't be decrypted with this YubiKey")
	}

	// Authenticate
	fmt.Printf("Enter PIN for YubiKey: ")
	pin, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println("")

	if err != nil {
		log.WithError(err).Fatal("Failed to read PIN")
	}
	if len(pin) == 0 {
		fmt.Printf("Empty PIN, ABORT!\n")
		return
	}
	if len(pin) < 6 || len(pin) > 8 {
		fmt.Printf("PIN should be between 6 and 8 characters long\n")
		return
	}

	var triesLeft C.int
	res = C.ykpiv_verify(state, (*C.char)(C.CBytes(pin)), &triesLeft)
	if res == C.YKPIV_WRONG_PIN {
		fmt.Printf("Wrong PIN. Tries left: %d\n", triesLeft)
		return
	} else if res != C.YKPIV_OK {
		log.Infof("Failed to verify PIN: %d.", res)
		return
	}

	// Decrypt the session key
	bufferLen := C.ulong(len(encryptedKey))
	out := C.malloc(bufferLen)
	in := C.CBytes(encryptedKey)
	res = C.ykpiv_decipher_data(state, (*C.uchar)(in), bufferLen, (*C.uchar)(out), &bufferLen, C.YKPIV_ALGO_RSA2048, C.uchar(yk_slot))
	if res != C.YKPIV_OK {
		log.Fatalf("Failed to decrypt session key: %d", res)
	}

	if bufferLen != 256 {
		log.Fatalf("Invalid output buffer len")
	}

	decryptedData := C.GoBytes(unsafe.Pointer(out), C.int(bufferLen))

	// Extract the key from padding
	if decryptedData[0] != 0 || decryptedData[1] != 2 || decryptedData[223] != 0 {
		log.Fatalf("Invalid padding")
	}

	decryptedKey := decryptedData[224:]

	// Decrypt payload
	block, err := aes.NewCipher(decryptedKey)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize AES cipher")
	}

	iv := envelopedData.EncryptedContent.Algorithm.Parameters.Bytes
	mode := cipher.NewCBCDecrypter(block, iv)

	plain := make([]byte, len(envelopedData.EncryptedContent.Content.Bytes))
	mode.CryptBlocks(plain, envelopedData.EncryptedContent.Content.Bytes)

	// Remove padding
	padLen := int(plain[len(plain)-1])
	if padLen > mode.BlockSize() {
		log.Fatal("Invalid padding")
	}

	plain = plain[:len(plain)-padLen]

	fmt.Printf("data=%s\n", plain)
}
