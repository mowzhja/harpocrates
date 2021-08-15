package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

// Generates data to have some users in the "DB"
func genData(filename string) error {
	fmt.Println("[+] Constructing records...")
	records := [][]string{
		{"user", "salt", "saltedPassword", "storedKey", "servKey"},
	}
	rec1 := makeRecord("alice", "alicespass")
	rec2 := makeRecord("bob", "bobspass")

	records = append(records, rec1)
	records = append(records, rec2)

	fmt.Println("[+] Creating file...")
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)

	fmt.Println("[+] Writing data...")
	for _, record := range records {
		if err := w.Write(record); err != nil {
			return err
		}
	}
	w.Flush()

	return nil
}

// Makes a record for CSV insertion given username and password.
func makeRecord(uname, passwd string) []string {
	salt := make([]byte, 32)
	rand.Read(salt)
	saltedPasswd := argon2.Key([]byte(passwd), salt, 1, 2_000_000, 2, 32)

	clientKey := hmac.New(sha256.New, saltedPasswd)
	clientKey.Write([]byte("Client Key"))
	servKey := hmac.New(sha256.New, saltedPasswd)
	servKey.Write([]byte("Server Key"))
	storedKey := sha256.Sum256(clientKey.Sum(nil))

	record := []string{
		uname,
		hex.EncodeToString(salt),
		hex.EncodeToString(saltedPasswd),
		hex.EncodeToString(storedKey[:]),
		hex.EncodeToString(servKey.Sum(nil))}

	return record
}

func main() {
	err := genData("user_data.csv")
	if err != nil {
		panic(err)
	}

	fmt.Println("[+] Done.")
}
