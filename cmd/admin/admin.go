package main

// #cgo LDFLAGS: -L../../ -llibrary
// #include "/home/mmt/src/Admin/lib_bridge.h"
import "C"

import (
	"fmt"
	"io"
	"net/http"
	"os"

	crypto_rand "crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
	"github.com/ttdung/admin/internal/common"
	"golang.org/x/crypto/nacl/box"

	policytree "github.com/ttdung/MatchAttributeWithPolicyTree/common"
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
	router.POST("/matchpolicy", matchPolicy)

	router.Run("localhost:8081")
}

func matchPolicy(c *gin.Context) {

	var req common.Policy
	if err := c.BindJSON(&req); err != nil {
		return
	}

	fmt.Println("request:", req)
	// fmt.Println("request Attr:", req.ATTR)

	var result common.ResPolicyMatching

	rs := policytree.EvaluatePolicyTree(req.ATTR, req.POLICY)

	fmt.Println("Matching:", rs)

	if rs == true {
		// load encrypted AES key file > decypt to get AES key > use AES key decrypt encrypted data file
		// encAESKey, err := os.ReadFile(req.STORE_ENC_KEY_FILE)
		// if err != nil {
		// 	panic(err)
		// }
		// Download the file from IPFS
		ipfsHash := req.STORE_ENC_KEY_FILE // Replace this with the actual IPFS hash from the upload response
		downloadedFilename := "/tmp/demo0/downloaded.dat"
		if err := common.DownloadFromIPFS(ipfsHash, downloadedFilename); err != nil {
			fmt.Printf("Failed to download from IPFS: %v", err)
		}
		// fmt.Println("Downloaded file successfully:", downloadedFilename)

		encAESKey, err := os.ReadFile(downloadedFilename)
		if err != nil {
			panic(err)
		}

		mpk, idx, ekey := common.LoadKey(req.UID)
		// fmt.Println("Uid:", req.UID)
		// fmt.Println("mpk:", mpk)
		// fmt.Println("idx:", idx)
		// fmt.Println("ABE key:", ekey)

		AESKey := common.AbeDecrypt(mpk, idx, ekey, string(encAESKey))

		fmt.Println("AES key:", AESKey)

		encDataFileName := "/tmp/demo0/doencrypted.txt"
		encData, err := os.ReadFile(encDataFileName)
		if err != nil {
			panic(err)
		}
		data := common.AESDecrypt(string(encData), AESKey)

		l := min(len(data), 250)

		result = common.ResPolicyMatching{MATCHING: rs,
			DATA: data[0:l]}

	} else {
		result = common.ResPolicyMatching{MATCHING: rs, DATA: ""}
	}

	c.IndentedJSON(http.StatusOK, result)
}

func register(c *gin.Context) {
	var req common.Attr
	if err := c.BindJSON(&req); err != nil {
		return
	}
	fmt.Println("request:", req)

	idx := req.UID
	fmt.Println("request UID:", req.UID)

	abekey := registerHandler(req.ATTR, idx)

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

func registerHandler(att string, idx string) string {

	common.InitializeOpenABE()

	abe := common.NewABE("CP-ABE")

	abe.ImportMSK(msk)
	abe.ImportMPK(mpk)

	abe.Genkey(att, idx)

	ekey := abe.ExportUserKey(idx)

	// fmt.Println("Genkey idx: ", idx)
	// fmt.Println("Ekey: ", ekey)

	common.ShutdownABE()

	return ekey
}
