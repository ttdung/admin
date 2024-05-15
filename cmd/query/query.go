package main

import (
	"encoding/json"
	"fmt"
	"os"

	restyv2 "github.com/go-resty/resty/v2"
	common "github.com/ttdung/admin/internal/common"
)

var senderPublicKey, senderPrivateKey *[32]byte

var gmpk, gidx, gkey string

func main() {

	fmt.Println("Query start...")

	args := os.Args
	if len(args) < 3 {
		panic("Usage: ./query <userid> <txid>")
	}

	uid := args[1]
	txid := args[2]

	filename := queryFilename(txid)
	fmt.Println("filename: ", filename)

	data := decrypt(uid, filename)
	fmt.Println("Data:", data)
}

func decrypt(uid string, filename common.QueryDataRes) string {

	encAESKey, err := os.ReadFile(filename.ENC_KEY_FILENAME)
	if err != nil {
		panic(err)
	}

	mpk, idx, ekey := common.LoadKey(uid)
	// fmt.Println("Uid:", req.UID)
	// fmt.Println("mpk:", mpk)
	// fmt.Println("idx:", idx)
	// fmt.Println("ABE key:", ekey)

	AESKey := common.AbeDecrypt(mpk, idx, ekey, string(encAESKey))

	fmt.Println("AES key:", AESKey)

	encData, err := os.ReadFile(filename.ENC_DATA_FILENAME)
	if err != nil {
		panic(err)
	}
	data := common.AESDecrypt(string(encData), AESKey)

	l := min(len(data), 1000)

	return data[0:l]
}

func queryFilename(txid string) common.QueryDataRes {
	// Create a resty client
	client := restyv2.New()

	// POST JSON string
	// No need to set content type, if you have client level setting
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(common.QueryData{
			TXID: txid,
		}).
		Post("http://localhost:8082/querydata")

	if err != nil {
		panic(err)
	}

	var result common.QueryDataRes

	if err := json.Unmarshal(resp.Body(), &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result
}
