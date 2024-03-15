package main

// #cgo LDFLAGS: -L../../ -llibrary
// #include "/home/mmt/src/Admin/lib_bridge.h"
import "C"

import (
	"fmt"
	"io"
	"net/http"

	crypto_rand "crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
	"github.com/ttdung/admin/internal/common"
	"golang.org/x/crypto/nacl/box"
)

var msk, mpk string

func main() {

	common.InitializeOpenABE()
	abe := common.NewABE("CP-ABE")
	abe.GenerateParams()
	msk = abe.ExportMSK()
	mpk = abe.ExportMPK()

	common.ShutdownABE()

	router := gin.Default()
	router.POST("/register", register)
	router.POST("/testabe", testABE_Encrypt)

	router.Run("localhost:8080")
}

func register(c *gin.Context) {
	var req common.Attr
	if err := c.BindJSON(&req); err != nil {
		return
	}
	fmt.Println("request:", req)

	idx, abekey := registerHandler(req.ATTR)

	pubKeyUser, err := hex.DecodeString(req.PK)
	if err != nil {
		panic(err)
	}

	var pkUser [32]byte
	copy(pkUser[:], pubKeyUser)

	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of repeats.
	var nonce [24]byte
	if _, err := io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	// This encrypts msg and appends the result to the nonce.
	senderPublicKey, senderPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		panic(err)
	}

	encryptedABEKey := box.Seal(nonce[:], []byte(abekey), &nonce, &pkUser, senderPrivateKey)

	pkAdmin := hex.EncodeToString(senderPublicKey[:])
	encryptedABEKeyStr := hex.EncodeToString(encryptedABEKey[:])

	fmt.Println("mpk:", mpk)
	fmt.Println("pkAmin:", senderPublicKey)
	fmt.Println("idx:", idx)
	// fmt.Println("encryptedABEKey:", encryptedABEKeyStr)

	res := common.Res{mpk, pkAdmin, idx, encryptedABEKeyStr}

	c.IndentedJSON(http.StatusOK, res)
}

func testABE_Encrypt(c *gin.Context) {
	var req common.Msg
	if err := c.BindJSON(&req); err != nil {
		return
	}
	fmt.Println("request:", req)

	ct := common.AbeEncrypt(mpk, req.ATTR, req.MSG)

	fmt.Println("testABE_Encrypt::Encrypted Msg: ", ct)
	c.IndentedJSON(http.StatusOK, common.EncryptedMsg{EMSG: ct})
}

func registerHandler(att string) (string, string) {

	common.InitializeOpenABE()

	abe := common.NewABE("CP-ABE")

	abe.ImportMSK(msk)
	abe.ImportMPK(mpk)

	idx := common.RandStringBytes(8)
	abe.Genkey(att, idx)

	ekey := abe.ExportUserKey(idx)

	fmt.Println("Genkey ok: ", idx)
	fmt.Println("Ekey ok: ", ekey)

	common.ShutdownABE()

	return idx, ekey
}
