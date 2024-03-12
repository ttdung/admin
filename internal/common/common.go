package common

// #cgo LDFLAGS: -L../../ -llibrary
// #include "../../lib_bridge.h"
import "C"

import (
	"math/rand/v2"
	"unsafe"
)

type ABE struct {
	ptr unsafe.Pointer
}

type Attr struct {
	PK   string `json:"pk"`
	ATTR string `json:"att"`
}

type Res struct {
	MPK     string `json:"mpk"`
	ADMINPK string `json:"adminpk"`
	IDX     string `json:"idx"`
	EKEY    string `json:"ekey"`
}

type Msg struct {
	ATTR string `json:"attr"`
	MSG  string `json:"msg"`
}

type EncryptedMsg struct {
	EMSG string `json:"emsg"`
}

func NewABE(abename string) ABE {
	var abe ABE
	abe.ptr = C.LIB_NewABE(C.CString(abename))
	return abe
}

func InitializeOpenABE() {
	C.LIB_InitializeOpenABE()
}

func ShutdownABE() {
	C.LIB_ShutdownOpenABE()
}

func (abe *ABE) GenerateParams() {
	C.LIB_generateParams(abe.ptr)
}

func (abe *ABE) Genkey(att string, key string) {
	latt := C.CString(att)
	lkey := C.CString(key)

	C.LIB_keygen(abe.ptr, latt, lkey)
}

func (abe *ABE) Encrypt(att string, pt string) string {
	latt := C.CString(att)
	lpt := C.CString(pt)

	return C.GoString(C.LIB_encrypt(abe.ptr, latt, lpt))
}

func (abe *ABE) Decrypt(key string, ct string) string {

	lkey := C.CString(key)
	lct := C.CString(ct)

	return C.GoString(C.LIB_decrypt(abe.ptr, lkey, lct))

}

func (abe *ABE) ExportMSK() string {

	return C.GoString(C.LIB_exportMSK(abe.ptr))
}

func (abe *ABE) ExportMPK() string {

	return C.GoString(C.LIB_exportMPK(abe.ptr))
}

func (abe *ABE) ImportMSK(key string) {

	lkey := C.CString(key)
	C.LIB_importMSK(abe.ptr, lkey)
}

func (abe *ABE) ImportMPK(key string) {

	lkey := C.CString(key)
	C.LIB_importMPK(abe.ptr, lkey)
}

func (abe *ABE) ImportUserKey(index string, key string) {

	lidx := C.CString(index)
	lkey := C.CString(key)
	C.LIB_importUserKey(abe.ptr, lidx, lkey)

}

func (abe *ABE) ExportUserKey(key string) string {

	lkey := C.CString(key)

	return C.GoString(C.LIB_exportUserKey(abe.ptr, lkey))
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.IntN(len(letterBytes))]
	}
	return string(b)
}

func AbeEncrypt(mpk string, accesstree string, data string) string {

	InitializeOpenABE()

	abe := NewABE("CP-ABE")

	abe.ImportMPK(mpk)

	ct := abe.Encrypt(accesstree, data)

	ShutdownABE()

	return ct
}

func AbeDecrypt(mpk string, idx string, ekey string, ct string) string {

	InitializeOpenABE()

	abe := NewABE("CP-ABE")

	abe.ImportMPK(mpk)

	abe.ImportUserKey(idx, ekey)

	pt := abe.Decrypt(idx, ct)

	ShutdownABE()

	return pt
}
