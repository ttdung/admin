package main

// #cgo LDFLAGS: -L. -llibrary
// #include "lib_bridge.h"
import "C"
import (
	"fmt"
	"net/http"
	"unsafe"

	"github.com/gin-gonic/gin"
)

type ABE struct {
	ptr unsafe.Pointer
}

func NewABE(abename string) ABE {
	var abe ABE
	abe.ptr = C.LIB_NewABE(C.CString(abename))
	return abe
}

func (abe ABE) generateParams() {
	C.LIB_generateParams(abe.ptr)
}

func (abe ABE) genkey(att string, key string) {
	latt := C.CString(att)
	lkey := C.CString(key)

	C.LIB_keygen(abe.ptr, latt, lkey)
}

func (abe ABE) encrypt(att string, pt string) string {
	latt := C.CString(att)
	lpt := C.CString(pt)

	return C.GoString(C.LIB_encrypt(abe.ptr, latt, lpt))
}

func (abe ABE) decrypt(key string, ct string) string {

	lkey := C.CString(key)
	lct := C.CString(ct)

	return C.GoString(C.LIB_decrypt(abe.ptr, lkey, lct))

}

// d, err := os.ReadFile("./sample.json")
// if err != nil {
// 	panic(err)
// }
// data := string(d)

/*
func main() {
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
*/

// album represents data about a record album.
type album struct {
	ID     string  `json:"id"`
	Title  string  `json:"title"`
	Artist string  `json:"artist"`
	Price  float64 `json:"price"`
}

// albums slice to seed record album data.
var albums = []album{
	{ID: "1", Title: "Blue Train", Artist: "John Coltrane", Price: 56.99},
	{ID: "2", Title: "Jeru", Artist: "Gerry Mulligan", Price: 17.99},
	{ID: "3", Title: "Sarah Vaughan and Clifford Brown", Artist: "Sarah Vaughan", Price: 39.99},
}

type attr struct {
	PK  string `json:"pk"`
	Att string `json:"att"`
}

func main() {
	router := gin.Default()
	router.POST("/register", register)
	router.GET("/albums", getAlbums)
	router.GET("/albums/:id", getAlbumByID)
	router.POST("/albums", postAlbums)

	router.Run("localhost:8080")
}

func register(c *gin.Context) {
	var user attr
	if err := c.BindJSON(&user); err != nil {
		return
	}
	fmt.Println("User %v", user)

	c.IndentedJSON(http.StatusOK, user.PK)
}

// getAlbums responds with the list of all albums as JSON.
func getAlbums(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, albums)
}

// postAlbums adds an album from JSON received in the request body.
func postAlbums(c *gin.Context) {
	var newAlbum album

	// Call BindJSON to bind the received JSON to
	// newAlbum.
	if err := c.BindJSON(&newAlbum); err != nil {
		return
	}

	// Add the new album to the slice.
	albums = append(albums, newAlbum)
	c.IndentedJSON(http.StatusCreated, newAlbum)
}

// getAlbumByID locates the album whose ID value matches the id
// parameter sent by the client, then returns that album as a response.
func getAlbumByID(c *gin.Context) {
	id := c.Param("id")

	// Loop through the list of albums, looking for
	// an album whose ID value matches the parameter.
	for _, a := range albums {
		if a.ID == id {
			c.IndentedJSON(http.StatusOK, a)
			return
		}
	}
	c.IndentedJSON(http.StatusNotFound, gin.H{"message": "album not found"})
}
