package main

import (
	"fmt"
	"os"
	"time"

	common "github.com/ttdung/admin/internal/common"
)

var senderPublicKey, senderPrivateKey *[32]byte

var gmpk, gidx, gkey string

func main() {

	fmt.Println("Encypt ...")

	var err error

	args := os.Args
	if len(args) < 4 {
		panic("Usage: ./enc <userid> <accesstree> <data_filename>")
	}

	uid := args[1]
	accesstree := args[2]
	datafilename := args[3]
	encDataFilename := fmt.Sprintf("%s.data.enc", datafilename)

	// Load data file then encrypt it using AES key
	data, err := os.ReadFile(datafilename)
	if err != nil {
		panic(err)
	}

	start := time.Now()

	// use ABEKey to encrypt AES_key
	gmpk, gidx, gkey = common.LoadKey(uid)
	encryptedData := common.AbeEncrypt(gmpk, accesstree, string(data))

	elapsed := time.Since(start)
	fmt.Printf("AbeEncrypt took: %s \n", elapsed)

	err = os.WriteFile(encDataFilename, []byte(encryptedData), 0644)
	if err != nil {
		panic(err)
	}

}
