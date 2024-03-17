package main

import (
	"fmt"
	"os"

	common "github.com/ttdung/admin/internal/common"
)

var senderPublicKey, senderPrivateKey *[32]byte

var gmpk, gidx, gkey string

func main() {

	fmt.Println("Do start...")

	var err error

	args := os.Args
	if len(args) < 4 {
		panic("Usage: ./du <userid> <filename> <accesstree>")
	}

	uid := args[1]
	filename := args[2]
	accesstree := args[3]

	// Load data file then encrypt it using AES key
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	encryptedFileData := common.AESEncrypt(string(data), common.SecretKey)
	encryptedFilename := "/tmp/demo0/encrypted.txt"
	err = os.WriteFile(encryptedFilename, []byte(encryptedFileData), 0644)
	if err != nil {
		panic(err)
	}

	// use ABEKey to encrypt AES secretkey
	gmpk, gidx, gkey = common.LoadKey(uid)
	encryptedKey := common.AbeEncrypt(gmpk, accesstree, common.SecretKey)
	encryptedKeyFilename := "/tmp/demo0/encryptedKey.txt"
	err = os.WriteFile(encryptedKeyFilename, []byte(encryptedKey), 0644)
	if err != nil {
		panic(err)
	}

	// test decrypt AES key
	// gmpk1, gidx1, gkey1 := common.LoadKey("du")
	// encAESKey, err := os.ReadFile("/tmp/demo0/encryptedKey.txt")
	// if err != nil {
	// 	panic(err)
	// }

	// pt := common.AbeDecrypt(gmpk1, gidx1, gkey1, string(encAESKey))
	// fmt.Println("Secret key: ", pt)

	// push to IPFS
	projectID := "InfuraProjectID"
	projectSecret := "InfuraProjectSecret"
	ipfsResponseFileData, err := common.UploadToIPFS(encryptedFilename, projectID, projectSecret)
	if err != nil {
		fmt.Printf("Failed to upload to IPFS: %v \n", err)
	}
	fmt.Println("Encrypted File uploaded to IPFS:", ipfsResponseFileData)

	ipfsResponseKey, err := common.UploadToIPFS(encryptedKeyFilename, projectID, projectSecret)
	if err != nil {
		fmt.Printf("Failed to upload to IPFS: %v \n", err)
	}
	fmt.Println("Encrypted Key uploaded to IPFS:", ipfsResponseKey)

	// Download the file from IPFS
	// ipfsHash := "ipfsHashHere" // Replace this with the actual IPFS hash from the upload response
	// downloadedFilename := "downloaded.dat"
	// if err := common.DownloadFromIPFS(ipfsHash, downloadedFilename, projectID, projectSecret); err != nil {
	// 	fmt.Printf("Failed to download from IPFS: %v \n", err)
	// }
	// fmt.Println("Downloaded file successfully:", downloadedFilename)
}
