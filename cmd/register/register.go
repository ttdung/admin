package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	crypto_rand "crypto/rand"

	"golang.org/x/crypto/nacl/box"

	restyv2 "github.com/go-resty/resty/v2"

	common "github.com/ttdung/admin/internal/common"
)

var senderPublicKey, senderPrivateKey *[32]byte

var gmpk, gidx, gkey string

func main() {

	if len(os.Args) < 3 {
		panic("Usage: register <userid> <attributes>")
	}

	uid := os.Args[1]
	attr := os.Args[2]

	fmt.Println("User ", uid, " register start...")
	fmt.Println(attr)

	var err error

	senderPublicKey, senderPrivateKey, err = box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		panic(err)
	}

	pk := hex.EncodeToString(senderPublicKey[:])

	gmpk, gidx, gkey = register(uid, pk, attr)

	common.StoreKey(uid, gmpk, gidx, gkey)
	// gmpk, gidx, gkey = common.LoadKey(uid)
	// testABE("xyz", "Hello!")
}

func testABE(attr string, data string) {

	// Create a resty client
	client := restyv2.New()

	// POST JSON string
	// No need to set content type, if you have client level setting

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(common.Msg{
			ATTR: attr,
			MSG:  data,
		}).
		Post("http://localhost:8080/testabe")

	if err != nil {
		panic(err)
	}

	var result common.EncryptedMsg
	if err := json.Unmarshal(resp.Body(), &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	fmt.Println("Encrypted msg from Admin:", result.EMSG)
	fmt.Println("mpk:", gmpk)
	fmt.Println("idx:", gidx)
	fmt.Println("ABEkey:", gkey)

	pt := common.AbeDecrypt(gmpk, gidx, gkey, result.EMSG)

	fmt.Println("Decrypt:", pt)

}

// This func returns:
// MPK
// IDX
// ABEKey
func register(uid string, pk string, attr string) (string, string, string) {

	// Create a resty client
	client := restyv2.New()

	// POST JSON string
	// No need to set content type, if you have client level setting

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(common.Attr{
			PK:   pk,
			ATTR: attr,
		}).
		Post("http://localhost:8081/register")

	if err != nil {
		panic(err)
	}

	var result common.Res

	if err := json.Unmarshal(resp.Body(), &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	pkAdmin, err := hex.DecodeString(result.ADMINPK)
	if err != nil {
		panic(err)
	}

	eKey, err := hex.DecodeString(result.EKEY)
	if err != nil {
		panic(err)
	}

	// The recipient can decrypt the message using their private key and the
	// sender's public key. When you decrypt, you must use the same nonce you
	// used to encrypt the message. One way to achieve this is to store the
	// nonce alongside the encrypted message. Above, we stored the nonce in the
	// first 24 bytes of the encrypted text.
	var decryptNonce [24]byte
	copy(decryptNonce[:], eKey[:24])

	var pkAdmin32 [32]byte
	copy(pkAdmin32[:], pkAdmin[:])

	decrypted, ok := box.Open(nil, eKey[24:], &decryptNonce, &pkAdmin32, senderPrivateKey)
	if !ok {
		panic("decryption error")
	}

	fmt.Println("MPK: ", result.MPK)
	fmt.Println("Index: ", result.IDX)
	fmt.Println("ABE-key: ", string(decrypted))

	return result.MPK, result.IDX, string(decrypted)
}

func printOutput(resp common.Res, err error) {
	fmt.Println(resp, err)
}
