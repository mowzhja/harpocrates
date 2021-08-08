// Coeus is one of the Titans of Greek mythology, whose name means "query", "questioning".
// As such, package coeus is responsible for the interaction with the filesystem (it queries it for information).
package coeus

import (
	"encoding/csv"
	"io"
	"os"
)

const DB_FILE = "user_data.csv"

func GetCorrespondingInfo(uname string) ([]byte, []byte, []byte, error) {
	var salt, storedKey, servKey []byte

	file, err := os.Open(DB_FILE)
	if err != nil {
		return nil, nil, nil, err
	}

	reader := csv.NewReader(file)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, nil, err
		}

		if record[0] == uname {
			// got a match
			salt = []byte(record[1])
			storedKey = []byte(record[2])
			servKey = []byte(record[3])
		}
	}

	return salt, storedKey, servKey, nil
}
