package main

import (
	"fmt"
	"os"

	common "github.com/ttdung/admin/internal/common"
)

var senderPublicKey, senderPrivateKey *[32]byte

var gmpk, gidx, gkey string

func main() {

	fmt.Println("Du start...")

	var err error

	args := os.Args
	if len(args) < 3 {
		panic("Usage: ./du <filename> <accesstree>")
	}

	filename := args[1]
	accesstree := args[2]

	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	encryptedFileData := common.AESEncrypt(string(data), common.SecretKey)

	encryptedFilename := "/tmp/demo0/ecrypted.txt"

	err = os.WriteFile(encryptedFilename, []byte(encryptedFileData), 0644)
	if err != nil {
		panic(err)
	}

	// use ABEKey to encrypt secretkey
	loadKey()
	encryptedKey := common.AbeEncrypt(gmpk, accesstree, common.SecretKey)

	encryptedKeyFilename := "/tmp/demo0/ecryptedKey.txt"

	err = os.WriteFile(encryptedKeyFilename, []byte(encryptedKey), 0644)
	if err != nil {
		panic(err)
	}

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

func loadKey() {
	mpk, err := os.ReadFile("/tmp/demo0/mpk.txt")
	if err != nil {
		panic(err)
	}
	gmpk = string(mpk)

	idx, err := os.ReadFile("/tmp/demo0/idx.txt")
	if err != nil {
		panic(err)
	}
	gidx = string(idx)

	key, err := os.ReadFile("/tmp/demo0/key.txt")
	if err != nil {
		panic(err)
	}
	gkey = string(key)
}
