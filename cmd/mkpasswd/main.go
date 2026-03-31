// cmd/mkpasswd generates a bcrypt password hash suitable for use in RGSTR_USERS.
//
// Usage:
//   go run ./cmd/mkpasswd alice mysecret
//   # Output: alice:$2a$12$...
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: mkpasswd <username> <password>\n")
		os.Exit(1)
	}
	username := os.Args[1]
	password := os.Args[2]

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("RGSTR_USERS=%s:%s\n", username, string(hash))
}
