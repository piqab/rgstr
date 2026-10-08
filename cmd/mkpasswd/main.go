// cmd/mkpasswd generates a bcrypt password hash suitable for use in RGSTR_USERS.
//
// Usage:
//
//	go run ./cmd/mkpasswd alice mysecret
//	docker run --rm --entrypoint /mkpasswd ghcr.io/piqab/rgstr alice mysecret
//	# Output: RGSTR_USERS='alice:$2a$10$...'
//
// The value is single-quoted so the hash's $ signs survive unchanged in a
// Docker Compose .env file, a shell, and a systemd EnvironmentFile.
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
	fmt.Printf("RGSTR_USERS='%s:%s'\n", username, hash)
}
