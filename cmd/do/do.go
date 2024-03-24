package main

import (
	"fmt"
	"os"

	common "github.com/ttdung/admin/internal/common"
)

var senderPublicKey, senderPrivateKey *[32]byte

var gmpk, gidx, gkey string

func main() {

	fmt.Println("Encypt & push to IPFS start...")

	var err error

	args := os.Args
	if len(args) < 4 {
		panic("Usage: ./enc <userid> <accesstree> <data filename>")
	}

	uid := args[1]
	accesstree := args[2]
	datafilename := args[3]
	enckeyfilename := "/tmp/demo0/doenckey.dat"

	// Load data file then encrypt it using AES key
	data, err := os.ReadFile(datafilename)
	if err != nil {
		panic(err)
	}

	encryptedFileData := common.AESEncrypt(string(data), common.SecretKey)
	// encryptedDataFilename := "/tmp/demo0/encrypted.txt"
	encryptedDataFilename := fmt.Sprintf("/tmp/demo0/%sencrypted.txt", uid)
	err = os.WriteFile(encryptedDataFilename, []byte(encryptedFileData), 0644)
	if err != nil {
		panic(err)
	}

	// use ABEKey to encrypt AES_key
	gmpk, gidx, gkey = common.LoadKey(uid)
	encryptedKey := common.AbeEncrypt(gmpk, accesstree, common.SecretKey)
	err = os.WriteFile(enckeyfilename, []byte(encryptedKey), 0644)
	if err != nil {
		panic(err)
	}

	ipfsResponseKey, err := common.UploadToIPFS(enckeyfilename)
	if err != nil {
		fmt.Printf("Failed to upload to IPFS: %v \n", err)
	}
	fmt.Println("Encrypted Key uploaded to IPFS:", ipfsResponseKey)

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
