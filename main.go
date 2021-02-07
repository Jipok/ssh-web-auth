package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSH_Info struct {
	keyType string
	keyData []byte
	session []byte
}

var (
	authorized_keys map[string]SSH_Info = make(map[string]SSH_Info)
	tokens                              = map[string][]string{}
	index_page		[]byte
)


func main() {
	// Parse ./authorized_keys
	file, err := os.Open("authorized_keys")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	// Read line by line
	scanner := bufio.NewScanner(file)
	users := []string{}
	for scanner.Scan() {
		if len(scanner.Text()) < 2 {
			continue
		}
		key, name, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, name)
		authorized_keys[name] = SSH_Info{key.Type(), key.Marshal(), nil}
	}
	log.Printf("Authorized users: %s", strings.Join(users, ", "))

	index_page = readBytes("index.html")

	// Load tokens
	data, err := ioutil.ReadFile("tokens.json")
	if err == nil {
		err = json.Unmarshal(data, &tokens)
		if err != nil { log.Fatalln(err) }
	}

	flag.Parse()
	go startWebServer()
	go startSshServer()
	select {}
}

func readBytes(name string) ([]byte) {
	file, err := os.Open(name)
    if err != nil {
		log.Fatal(err)
    }
    defer file.Close()

    stats, err := file.Stat()
    if err != nil {
        log.Fatal(err)
    }

    var size int64 = stats.Size()
    bytes := make([]byte, size)

    bufr := bufio.NewReader(file)
	_,err = bufr.Read(bytes)
	if err != nil {
		log.Fatal(err)
    }
	return bytes
}