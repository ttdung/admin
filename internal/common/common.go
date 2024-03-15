package common

// #cgo LDFLAGS: -L../../ -llibrary
// #include "../../lib_bridge.h"
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	rand1 "crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand/v2"
	"os"
	"unsafe"

	"github.com/valyala/fasthttp"
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

func AESEncrypt(plaintext string, secretKey string) string {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand1.Read(nonce)
	if err != nil {
		panic(err)
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext)
}

var (
	// We're using a 32 byte long secret key.
	// This is probably something you generate first
	// then put into and environment variable.
	SecretKey string = "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"
)

func AESDecrypt(ciphertext string, secretKey string) string {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		panic(err)
	}

	return string(plaintext)
}

// basicAuthHeader creates a basic authentication header value.
func basicAuthHeader(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// UploadToIPFS uploads a file to IPFS via the Infura API.
func UploadToIPFS(filename string, projectID, projectSecret string) (string, error) {
	url := "https://ipfs.infura.io:5001/api/v0/add"

	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod("POST")
	req.SetRequestURI(url)
	req.Header.SetContentType("multipart/form-data")
	req.Header.Set("Authorization", basicAuthHeader(projectID, projectSecret))
	req.SetBody(content)

	if err := fasthttp.Do(req, resp); err != nil {
		return "", err
	}

	if statusCode := resp.StatusCode(); statusCode != fasthttp.StatusOK {
		return "", fmt.Errorf("bad status: %d - %s", statusCode, string(fasthttp.StatusMessage(statusCode)))
	}

	return string(resp.Body()), nil
}

// DownloadFromIPFS downloads a file from IPFS via the Infura API given the file's hash.
func DownloadFromIPFS(ipfsHash, outputFilename string, projectID, projectSecret string) error {
	url := fmt.Sprintf("https://ipfs.infura.io:5001/api/v0/cat?arg=%s", ipfsHash)

	// Prepare the request
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod("POST")
	req.SetRequestURI(url)
	req.Header.Set("Authorization", basicAuthHeader(projectID, projectSecret))

	// Execute the request
	if err := fasthttp.Do(req, resp); err != nil {
		return err
	}

	// Check the response status code
	if statusCode := resp.StatusCode(); statusCode != fasthttp.StatusOK {
		return fmt.Errorf("bad status: %d - %s", statusCode, string(fasthttp.StatusMessage(statusCode)))
	}

	// Write the response body to an output file
	if err := ioutil.WriteFile(outputFilename, resp.Body(), 0644); err != nil {
		return err
	}

	return nil
}
