package main

import "C"
import (
	"unsafe"
)

type ABE struct {
	ptr unsafe.Pointer
}

type Attr struct {
	PK  string `json:"pk"`
	Att string `json:"att"`
}

var msk, mpk, ukey string

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var messages = make(chan Attr)
var keys = make(chan string)

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

func (abe *ABE) generateParams() {
	C.LIB_generateParams(abe.ptr)
}

func (abe *ABE) genkey(att string, key string) {
	latt := C.CString(att)
	lkey := C.CString(key)

	C.LIB_keygen(abe.ptr, latt, lkey)
}

func (abe *ABE) encrypt(att string, pt string) string {
	latt := C.CString(att)
	lpt := C.CString(pt)

	return C.GoString(C.LIB_encrypt(abe.ptr, latt, lpt))
}

func (abe *ABE) decrypt(key string, ct string) string {

	lkey := C.CString(key)
	lct := C.CString(ct)

	return C.GoString(C.LIB_decrypt(abe.ptr, lkey, lct))

}

func (abe *ABE) exportMSK() string {

	return C.GoString(C.LIB_exportMSK(abe.ptr))
}

func (abe *ABE) exportMPK() string {

	return C.GoString(C.LIB_exportMPK(abe.ptr))
}

func (abe *ABE) importMSK(key string) {

	lkey := C.CString(key)
	C.LIB_importMSK(abe.ptr, lkey)
}

func (abe *ABE) importMPK(key string) {

	lkey := C.CString(key)
	C.LIB_importMPK(abe.ptr, lkey)
}

func (abe *ABE) importUserKey(index string, key string) {

	lidx := C.CString(index)
	lkey := C.CString(key)
	C.LIB_importUserKey(abe.ptr, lidx, lkey)

}

func (abe *ABE) exportUserKey(key string) string {

	lkey := C.CString(key)

	return C.GoString(C.LIB_exportUserKey(abe.ptr, lkey))
}
