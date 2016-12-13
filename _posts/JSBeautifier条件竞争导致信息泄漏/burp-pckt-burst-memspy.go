package main

import "fmt"
import "net"
import "bufio"
//import "crypto/md5"
import "strings"
//import	"io"
import	"net/http"
import "sync"
//import "time"
import "math/rand"
//import "unicode/utf8"
import "io/ioutil"

type gMap_s struct{
	conn	net.Conn
	buff	*bufio.ReadWriter
}
var gMap = map[int]gMap_s{}
var mapMutex sync.Mutex

var connLimit int

var wg sync.WaitGroup

var resp string
var respBase string

var batchId int

func serveSpyHtml(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	b, err := ioutil.ReadFile("spy.html")
	if err != nil {
		fmt.Println("404")
		return
	}
	fmt.Fprintf(w, string(b))
}

func main() {
	batchId = 1;
	// Load the response in memory
	respBase = "HTTP/1.1 200 OK\nMeta:%s:%d\nContent-Type: text/html\n\n<!"// + strings.Repeat("A", 256) + ">"

	connLimit = 20
	wg.Add(connLimit)

	x := 0;

	http.HandleFunc("/", func (w http.ResponseWriter, r *http.Request){

		fmt.Printf("%X.", x)

		defer wg.Done()
		mapMutex.Lock()
		hj := w.(http.Hijacker)
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			return
		}

		gMap[x] = gMap_s{conn: conn, buff: bufrw}
		x++

		if(x == connLimit) {
			x=0
		}
		mapMutex.Unlock()
	})
	http.HandleFunc("/memspy", serveSpyHtml)

	go http.ListenAndServe(":8000", nil)

	wg.Wait()
	wgFin()
}

func wgFin(){
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"

	mapMutex.Lock()
	for i := 0; i < connLimit; i++ {

		char := string(chars[rand.Intn(len(chars))])
		resp = fmt.Sprintf(respBase, char, batchId) + strings.Repeat(char, 1024) + ">"
		batchId++
		gMap[i].buff.WriteString(resp)
		gMap[i].buff.Flush()
		gMap[i].conn.Close()
		delete(gMap, i)
	}

	fmt.Print("X")

	wg.Add(connLimit)
	mapMutex.Unlock()

	wg.Wait()
	wgFin()

}
