package main

/*
#cgo linux CFLAGS: -I/usr/local/include/ykpiv -Wall
#cgo linux LDFLAGS: -lykpiv
#include <stdlib.h>
#include <ykpiv.h>
*/
import "C"

import (
	"crypto/x509"
	"unsafe"

	"github.com/pkg/errors"
)

type YkPiv struct {
	state *C.ykpiv_state
}

func YkPivGetError(res C.ykpiv_rc) string {
	return C.GoString(C.ykpiv_strerror(res))
}

func YkPivInit(reader string, verbosity int) (*YkPiv, error) {
	var state *C.ykpiv_state

	res := C.ykpiv_init(&state, C.int(verbosity))
	if res != C.YKPIV_OK {
		return nil, errors.Errorf("Failed to initialize yubico library: %s", YkPivGetError(res))
	}

	res = C.ykpiv_connect(state, C.CString(reader))
	if res != C.YKPIV_OK {
		return nil, errors.Errorf("Failed to connect to yubikey: %s", YkPivGetError(res))
	}

	return &YkPiv{state}, nil
}

func (y *YkPiv) GetCertificate(slot int64) (*x509.Certificate, error) {
	var certificateLen C.ulong
	var certificatePtr *C.uchar
	res := C.ykpiv_util_read_cert(y.state, C.uchar(slot), &certificatePtr, &certificateLen)
	if res != C.YKPIV_OK {
		return nil, errors.Errorf("Failed to read certificate: %s", YkPivGetError(res))
	}

	certificateData := C.GoBytes(unsafe.Pointer(certificatePtr), C.int(certificateLen))
	certificate, err := x509.ParseCertificate(certificateData)
	if err != nil {
		return nil, errors.Errorf("Failed to parse certificate: %s", YkPivGetError(res))
	}

	return certificate, nil
}

func (y *YkPiv) VerifyPIN(pin []byte) error {
	if len(pin) < 6 || len(pin) > 8 {
		return errors.New("PIN should be between 6 and 8 characters long")
	}

	cPin := C.CBytes(pin)
	defer C.free(cPin)

	var triesLeft C.int
	res := C.ykpiv_verify(y.state, (*C.char)(cPin), &triesLeft)

	if res == C.YKPIV_WRONG_PIN {
		return errors.Errorf("Wrong PIN. Tries left: %d", triesLeft)
	} else if res != C.YKPIV_OK {
		return errors.New(YkPivGetError(res))
	}

	return nil
}

func (y *YkPiv) Decrypt(slot int64, data []byte) ([]byte, error) {
	in := C.CBytes(data)
	defer C.free(in)

	bufferLen := C.ulong(len(data))
	out := C.malloc(bufferLen)
	defer C.free(out)

	res := C.ykpiv_decipher_data(y.state, (*C.uchar)(in), bufferLen, (*C.uchar)(out), &bufferLen, C.YKPIV_ALGO_RSA2048, C.uchar(slot))
	if res != C.YKPIV_OK {
		return nil, errors.New(YkPivGetError(res))
	}

	if bufferLen != 256 {
		return nil, errors.New("Invalid output buffer len")
	}

	decryptedData := C.GoBytes(unsafe.Pointer(out), C.int(bufferLen))

	// Extract the key from padding
	if decryptedData[0] != 0 || decryptedData[1] != 2 || decryptedData[223] != 0 {
		return nil, errors.New("Invalid padding")
	}

	return decryptedData[224:], nil
}
