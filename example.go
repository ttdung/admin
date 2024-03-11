package main

// #cgo LDFLAGS: -L. -llibrary
// #include "lib_bridge.h"
import "C"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

type MKey struct {
	MSK *ecdsa.PrivateKey `json:"msk"`
	MPK ecdsa.PublicKey   `json:"mpk"`
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// d, err := os.ReadFile("./sample.json")
// if err != nil {
// 	panic(err)
// }
// data := string(d)

func maintest() {
	abe := NewABE("CP-ABE")

	abe.generateParams() // (MPK, MSK)

	abe.genkey("student|math", "key_alice")
	abe.genkey("student|CS", "key_bob")

	data := "hello world"

	ct := abe.encrypt("(student) and (math or EE)", data)

	pt := abe.decrypt("key_alice", ct)

	if pt == data {
		fmt.Printf("Decrypt Successful pt = %v \n", pt)
	} else {
		fmt.Println("Fail to decrypt")
	}
}
