package main

// #cgo LDFLAGS: -L. -llibrary
// #include "lib_bridge.h"
import "C"
import (
	"fmt"
	"net/http"
	"unsafe"

	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"math/rand/v2"

	"github.com/gin-gonic/gin"
)

type PrivateKey struct {
	PublicKey
	D *big.Int
}
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type ABE struct {
	ptr unsafe.Pointer
}

func NewABE(abename string) ABE {
	var abe ABE
	abe.ptr = C.LIB_NewABE(C.CString(abename))
	return abe
}

func (abe ABE) generateParams() {
	C.LIB_generateParams(abe.ptr)
}

func (abe ABE) genkey(att string, key string) {
	latt := C.CString(att)
	lkey := C.CString(key)

	C.LIB_keygen(abe.ptr, latt, lkey)
}

func (abe ABE) encrypt(att string, pt string) string {
	latt := C.CString(att)
	lpt := C.CString(pt)

	return C.GoString(C.LIB_encrypt(abe.ptr, latt, lpt))
}

func (abe ABE) decrypt(key string, ct string) string {

	lkey := C.CString(key)
	lct := C.CString(ct)

	return C.GoString(C.LIB_decrypt(abe.ptr, lkey, lct))

}

func (abe ABE) exportMSK() string {

	return C.GoString(C.LIB_exportMPK(abe.ptr))
}

func (abe ABE) exportMPK() string {

	return C.GoString(C.LIB_exportMPK(abe.ptr))
}

func (abe ABE) importMSK(key string) {

	lkey := C.CString(key)
	C.LIB_importMSK(abe.ptr, lkey)
}

func (abe ABE) importMPK(key string) {

	lkey := C.CString(key)
	C.LIB_importMPK(abe.ptr, lkey)
}

// d, err := os.ReadFile("./sample.json")
// if err != nil {
// 	panic(err)
// }
// data := string(d)

/*
func main() {
	abe := NewABE("CP-ABE")

	abe.generateParams() // (MPK, MSK)

	abe.genkey("student|math", "key_alice")
	abe.genkey("student|CS", "key_bob")

	data := "hello world"

	ct := abe.encrypt("(student) and (math or EE)", data)

	pt := abe.decrypt("key_alice", ct)

	if pt == data {
		fmt.Printf("Decrypt Successful pt = %v \n", pt)
	} else {
		fmt.Println("Fail to decrypt")
	}
}
*/

type attr struct {
	PK  string `json:"pk"`
	Att string `json:"att"`
}

type MKey struct {
	MSK *ecdsa.PrivateKey `json:"msk"`
	MPK ecdsa.PublicKey   `json:"mpk"`
}

var gabe ABE
var msk, mpk string

func newABE() *ABE {

	abe := NewABE("CP-ABE")
	abe.generateParams()

	return &abe
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.IntN(len(letterBytes))]
	}
	return string(b)
}

func main() {

	gabe = NewABE("CP-ABE")
	gabe.generateParams()
	gabe.genkey("qwe", "asd")
	fmt.Println("Genkey main OK")
	// msk = gabe.exportMSK()
	// mpk = gabe.exportMPK()
	// gabe.genkey("helo", "key")
	// fmt.Println("genkey ok")

	router := gin.Default()
	router.POST("/register", register)

	router.Run("localhost:8080")

}

func register(c *gin.Context) {
	var user attr
	if err := c.BindJSON(&user); err != nil {
		return
	}
	fmt.Println("User:", user)

	key := RandStringBytes(8)

	// abe := NewABE("CP-ABE")
	// abe.importMPK(mpk)
	// abe.importMSK(msk)

	//gabe.genkey("abc", "key1")

	// fmt.Println("ABEKey: ", key)
	// fmt.Println("User att: ", user.Att)

	gabe.genkey("abc", "key1")

	c.IndentedJSON(http.StatusOK, key)
}
