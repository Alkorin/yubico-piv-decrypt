package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh/terminal"
)

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s: ", os.Args[0])
	fmt.Fprintf(os.Stderr, format, a...)
	fmt.Fprintln(os.Stderr)
	os.Exit(-1)
}

func main() {
	// Parse args
	yk_verbosity := flag.Int("verbose", 0, "Print more information")
	yk_reader := flag.String("reader", "Yubikey", "Only use a matching reader")
	yk_slot_string := flag.String("slot", "9a", "What key slot to operate on")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "<file>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) != 1 {
		flag.Usage()
		return
	}

	yk_slot, err := strconv.ParseInt(*yk_slot_string, 16, 64)
	if err != nil {
		fatal("Invalid slot value: %q, allowed values: '9a', '9c', '9d', '9e', '82', '83', '84', '85', '86', '87', '88','89', '8a', '8b', '8c', '8d', '8e','8f', '90', '91', '92', '93', '94','95', 'f9'", *yk_slot_string)
	}

	// Parse file
	envelopedData, err := ParsePEMFile(flag.Arg(0))
	if err != nil {
		fatal("Failed to parse file %q: %s", flag.Arg(0), err)
	}

	// TODO: support other encryption schemes
	if !envelopedData.EncryptedContent.Algorithm.Algorithm.Equal(oidAES256CBC) {
		fatal("Only AES-256 CBC is supported")
	}

	yk, err := YkPivInit(*yk_reader, *yk_verbosity)
	if err != nil {
		fatal("Failed to initialize yubikey: %s", err)
	}

	// Read slot certificate
	certificate, err := yk.GetCertificate(yk_slot)
	if err != nil {
		fatal("Failed to get certificate of slot 0x%x: %s", yk_slot, err)
	}

	// Find a matching recipient in PKCS file
	var encryptedKey []byte
	for _, v := range envelopedData.Recipients {
		if v.Issuer.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			encryptedKey = v.EncryptedKey
		}
	}
	if encryptedKey == nil {
		fatal("File can't be decrypted with this YubiKey")
	}

	// Ask PIN
	fmt.Fprintf(os.Stderr, "Enter PIN: ")
	pin, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatal("Failed to read PIN")
	}

	if len(pin) == 0 {
		fatal("Empty PIN, ABORT!")
	}

	// Verify PIN
	err = yk.VerifyPIN(pin)
	if err != nil {
		fatal("Failed to verify pin: %s", err)
	}

	// Decrypt the session key
	decryptedKey, err := yk.Decrypt(yk_slot, encryptedKey)
	if err != nil {
		fatal("Failed to decrypt session key: %s", err)
	}

	// Decrypt the payload using AES256-CBC
	block, err := aes.NewCipher(decryptedKey)
	if err != nil {
		fatal("Failed to create cipher: %s", err)
	}

	mode := cipher.NewCBCDecrypter(block, envelopedData.EncryptedContent.Algorithm.Parameters.Bytes)

	plain := make([]byte, len(envelopedData.EncryptedContent.Content.Bytes))
	mode.CryptBlocks(plain, envelopedData.EncryptedContent.Content.Bytes)

	// Remove PKCS#7 padding
	padLen := int(plain[len(plain)-1])
	if padLen > mode.BlockSize() {
		fatal("Invalid padding")
	}

	// Output data
	os.Stdout.Write(plain[:len(plain)-padLen])
}
