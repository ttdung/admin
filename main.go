package main

// #cgo LDFLAGS: -L. -llibrary
// #include "lib_bridge.h"
import "C"
import (
	"fmt"
	"net/http"
	"unsafe"

	"math/rand/v2"

	"github.com/gin-gonic/gin"
)

type ABE struct {
	ptr unsafe.Pointer
}

type Attr struct {
	PK  string `json:"pk"`
	Att string `json:"att"`
}

type Res struct {
	Idx  string `json:"idx"`
	Ekey string `json:"ekey"`
}

var msk, mpk string

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

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.IntN(len(letterBytes))]
	}
	return string(b)
}

func main() {

	InitializeOpenABE()
	abe := NewABE("CP-ABE")
	abe.generateParams()

	msk = abe.exportMSK()
	mpk = abe.exportMPK()

	ShutdownABE()

	router := gin.Default()
	router.POST("/register", register)

	router.Run("localhost:8080")
}

func register(c *gin.Context) {
	var req Attr
	if err := c.BindJSON(&req); err != nil {
		return
	}
	fmt.Println("request:", req)

	idx, key := registerHandler(req.Att)

	ct := abeEncrypt("aaa or bbb or xyz", "hello")

	pt := abeDecrypt(idx, key, ct)

	fmt.Println("pt: ", pt)

	res := Res{idx, key}

	c.IndentedJSON(http.StatusOK, res)
}

func registerHandler(att string) (string, string) {

	InitializeOpenABE()

	abe := NewABE("CP-ABE")

	fmt.Println("mpk:", mpk, "  msk:", msk)
	abe.importMSK(msk)
	abe.importMPK(mpk)

	idx := RandStringBytes(8)
	abe.genkey(att, idx)

	ekey := abe.exportUserKey(idx)

	fmt.Println("Genkey ok: ", idx)
	fmt.Println("Ekey ok: ", ekey)

	ShutdownABE()

	return idx, ekey
}

func abeEncrypt(accesstree string, data string) string {

	InitializeOpenABE()

	abe := NewABE("CP-ABE")

	abe.importMPK(mpk)

	ct := abe.encrypt(accesstree, data)

	ShutdownABE()

	return ct
}

func abeDecrypt(idx string, ekey string, ct string) string {

	InitializeOpenABE()

	abe := NewABE("CP-ABE")

	abe.importMPK(mpk)

	abe.importUserKey(idx, ekey)

	pt := abe.decrypt(idx, ct)

	ShutdownABE()

	return pt
}
