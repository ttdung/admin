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

	fmt.Println("Encypt & push to IPFS start...")

	var err error

	args := os.Args
	if len(args) < 4 {
		panic("Usage: ./enc <userid> <accesstree> <data_filename>")
	}

	uid := args[1]
	accesstree := args[2]
	datafilename := args[3]
	encKeyFilename := fmt.Sprintf("%s.key.enc", datafilename)
	encDataFilename := fmt.Sprintf("%s.data.enc", datafilename)

	// Load data file then encrypt it using AES key
	data, err := os.ReadFile(datafilename)
	if err != nil {
		panic(err)
	}

	encryptedFileData := common.AESEncrypt(string(data), common.SecretKey)
	// encryptedDataFilename := "/tmp/demo0/encrypted.txt"
	err = os.WriteFile(encDataFilename, []byte(encryptedFileData), 0644)
	if err != nil {
		panic(err)
	}

	// use ABEKey to encrypt AES_key
	gmpk, gidx, gkey = common.LoadKey(uid)
	encryptedKey := common.AbeEncrypt(gmpk, accesstree, common.SecretKey)
	err = os.WriteFile(encKeyFilename, []byte(encryptedKey), 0644)
	if err != nil {
		panic(err)
	}

	fileid := store(uid, encKeyFilename, encDataFilename)
	fmt.Printf("FileID: %s \n", string(fileid[:]))
	// ipfsResponseKey, err := common.UploadToIPFS(encKeyFilename)
	// if err != nil {
	// 	fmt.Printf("Failed to upload to IPFS: %v \n", err)
	// }
	// fmt.Println("Encrypted Key uploaded to IPFS:", ipfsResponseKey)

	// test decrypt AES key
	// gmpk1, gidx1, gkey1 := common.LoadKey("du")
	// encAESKey, err := os.ReadFile("/tmp/demo0/encryptedKey.txt")
	// if err != nil {
	// 	panic(err)
	// }

	// pt := common.AbeDecrypt(gmpk1, gidx1, gkey1, string(encAESKey))
	// fmt.Println("Secret key: ", pt)

	// push to IPFS
	// ipfsResponseFileData, err := common.UploadToIPFS(encryptedDataFilename)
	// if err != nil {
	// 	fmt.Printf("Failed to upload to IPFS: %v \n", err)
	// }
	// fmt.Println("Encrypted File uploaded to IPFS:", ipfsResponseFileData)

	// Download the file from IPFS
	// ipfsHash := ipfsResponseKey["Hash"] // Replace this with the actual IPFS hash from the upload response
	// downloadedFilename := "/tmp/demo0/downloaded.dat"
	// if err := common.DownloadFromIPFS(ipfsHash, downloadedFilename); err != nil {
	// 	fmt.Printf("Failed to download from IPFS: %v", err)
	// }
	// fmt.Println("Downloaded file successfully:", downloadedFilename)

	// ipfsHash := "ipfsHashHere" // Replace this with the actual IPFS hash from the upload response
	// downloadedFilename := "downloaded.dat"
	// if err := common.DownloadFromIPFS(ipfsHash, downloadedFilename, projectID, projectSecret); err != nil {
	// 	fmt.Printf("Failed to download from IPFS: %v \n", err)
	// }
	// fmt.Println("Downloaded file successfully:", downloadedFilename)
}

func store(uid string, encKeyFilename string, encDataFilename string) string {

	// Create a resty client
	client := restyv2.New()

	// POST JSON string
	// No need to set content type, if you have client level setting
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(common.Store{
			UID:               uid,
			ENC_KEY_FILENAME:  encKeyFilename,
			ENC_DATA_FILENAME: encDataFilename,
		}).
		Post("http://localhost:8082/store")

	if err != nil {
		panic(err)
	}

	var result common.StoreRes

	if err := json.Unmarshal(resp.Body(), &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.FILEID
}
