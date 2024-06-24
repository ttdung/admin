package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	bbsplus "github.com/trustbloc/bbs-signature-go/bbs12381g2pub"
)

func main() {
	pubKey, privKey, err := generateKeyPairRandom()
	fmt.Println("pubKey: ", hex.EncodeToString(pubKey.PointG2.Bytes())) //hex.EncodeToString(pubkey[:])
	fmt.Println("privKey: ", hex.EncodeToString(privKey.FR.Bytes()))

	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		fmt.Println("Error: ", err.Error())
	}

	messagesBytes := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
		[]byte("message4"),
	}
	bbs := bbsplus.New()

	fmt.Println("messagesBytes:", string(messagesBytes[0]))
	fmt.Println("messagesBytes:", string(messagesBytes[1][:]))

	signatureBytes, err := bbs.Sign(messagesBytes, privKeyBytes)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Signature:", hex.EncodeToString(signatureBytes))

	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		panic(err.Error())
	}

	err = bbs.Verify(messagesBytes, signatureBytes, pubKeyBytes)
	if err != nil {
		panic(err.Error())
	} else {
		fmt.Println("Verify ok!")
	}

	nonce := []byte("nonce")
	revealedIndexes := []int{0, 2}
	proofBytes, err := bbs.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("proofBytes: ", hex.EncodeToString(proofBytes))
	}

	revealedMessages := make([][]byte, len(revealedIndexes))
	for i, ind := range revealedIndexes {
		revealedMessages[i] = messagesBytes[ind]
		fmt.Println("revealedMessages:", string(revealedMessages[i]))
	}

	err = bbs.VerifyProof(revealedMessages, proofBytes, nonce, pubKeyBytes)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("Verify proof ok!")
	}

}

func generateKeyPairRandom() (*bbsplus.PublicKey, *bbsplus.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	return bbsplus.GenerateKeyPair(sha256.New, seed)
}
