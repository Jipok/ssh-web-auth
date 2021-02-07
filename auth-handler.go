package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)


func red(in string) string {
	return fmt.Sprintf("\033[0;31m%s\033[0;0m", in)
}

// Contains tells whether a contains x.
func Contains(a []string, x string) bool {
    for _, n := range a {
        if x == n {
            return true
        }
    }
    return false
}

func BuildAuthHandler(handler http.Handler) (http.Handler) {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie("ssh_auth_token")
		if err == nil {
			for name, array := range tokens {
				if Contains(array, cookie.Value) {
					req.Header.Add("REMOTE_USER", name)
					req.Header.Add("X-Forwarded-User", name)
					handler.ServeHTTP(w, req)
					return 
				}
			}
		}
		w.Write(index_page)
	})
}

func AddToken(username string, token string) bool {
	if len(token) < 20 { return false }
	for _, array := range tokens {
		if Contains(array, token) { return false }
	}
	tokens[username] = append(tokens[username], token)
	log.Printf("New token for '%s': %s", username, token)

	// Save to file
	data, _ := json.Marshal(tokens)
	file, err := os.Create("tokens.json")
	if err != nil { log.Fatalf("Failed to save tokens: %s", err) }
	file.Write(data)
	file.Close()

	return true
}
