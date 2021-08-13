package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"os"

	"golang.org/x/crypto/argon2"
)

// Generates data to have some users in the "DB"
func genData(filename string) error {
	records := [][]string{
		{"user", "salt", "saltedPassword", "storedKey", "servKey"},
	}
	rec1 := makeRecord("alice", "alicespass")
	rec2 := makeRecord("bob", "bobspass")

	records = append(records, rec1)
	records = append(records, rec2)

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)

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

	record := []string{uname, string(salt), string(saltedPasswd), string(storedKey[:]), string(servKey.Sum(nil))}

	return record
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	err = genData(home + "/Programming/harpocrates/server/coeus/user_data.csv")
	if err != nil {
		panic(err)
	}

}
