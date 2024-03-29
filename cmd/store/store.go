package main

import (
	"fmt"
	"net/http"

	"crypto/sha256"
	// "encoding/base64"
	"encoding/hex"

	"github.com/gin-gonic/gin"
	internalcommon "github.com/ttdung/admin/internal/common"
)

type file struct {
	uid             string
	enckeyfilename  string
	encdatafilename string
}

var m = make(map[string]file)
var read_req = make(map[string]string)

func main() {

	RestAPIListen()
}

func RestAPIListen() {
	router := gin.Default()
	router.POST("/store", store)
	router.POST("/txreadreq", txreadreq)
	router.POST("/querydata", querydata)

	router.Run("localhost:8082")
}

// handle DU want to download data => input txid, return ecnKeyFilename & encDataFilename
func querydata(c *gin.Context) {
	var req internalcommon.ReadReq
	if err := c.BindJSON(&req); err != nil {
		return
	}

	fmt.Println("request txid:", req.TXID)

	fileid := read_req[req.TXID]
	fmt.Println("request fileid:", fileid)

	result := internalcommon.QueryDataRes{
		ENC_KEY_FILENAME:  m[fileid].enckeyfilename,
		ENC_DATA_FILENAME: m[fileid].encdatafilename,
	}

	c.IndentedJSON(http.StatusOK, result)
}

// handle new TX REQ_READ to Blockchain
func txreadreq(c *gin.Context) {
	var req internalcommon.ReadReq
	if err := c.BindJSON(&req); err != nil {
		return
	}

	fmt.Println("request txid:", req.TXID)
	fmt.Println("request fileid:", req.FILEID)
	fmt.Println("value: ", req.VALUE)

	read_req[req.TXID] = req.FILEID
}

func store(c *gin.Context) {

	var req internalcommon.Store
	if err := c.BindJSON(&req); err != nil {
		return
	}
	fmt.Println("request:", req)

	fileid := getHash(req.ENC_KEY_FILENAME)

	m[fileid] = file{
		uid:             req.UID,
		enckeyfilename:  req.ENC_KEY_FILENAME,
		encdatafilename: req.ENC_DATA_FILENAME}

	fmt.Println("fileid: ", fileid)
	fmt.Printf("map[%s]:\n", string(fileid[:]))
	fmt.Println("file entry: ", m[fileid])

	var result = internalcommon.StoreRes{FILEID: fileid}

	c.IndentedJSON(http.StatusOK, result)
}

func getHash(str string) string {

	h := sha256.New()
	h.Write([]byte(str))

	rs := hex.EncodeToString(h.Sum(nil))

	res := fmt.Sprintf("0x%s", rs)
	return res
	// return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
