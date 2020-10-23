package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	ExitOk     int = iota
	ExitError
)

var (
	encryptFlag  bool
	decryptFlag  bool
	fileFlag 	string
)

func createHashKey(key string) []byte {
	hashedKey := sha256.Sum256([]byte(key))
	return hashedKey[:]
}

func encryptData(data []byte, passphrase string) (encryptedData []byte, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(createHashKey(passphrase)); err != nil {
		return encryptedData, err
	}

	var gcm cipher.AEAD
	if gcm, err = cipher.NewGCM(block); err != nil {
		return encryptedData, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return encryptedData, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decryptData(data []byte, passphrase string) (decryptedData []byte, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(createHashKey(passphrase)); err != nil {
		return decryptedData, err
	}

	var gcm cipher.AEAD
	if gcm, err = cipher.NewGCM(block); err != nil {
		return decryptedData, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	if decryptedData, err = gcm.Open(nil, nonce, ciphertext, nil); err != nil {
		return decryptedData, err
	}

	return decryptedData, nil
}

func encryptFile(filename string) (err error) {
	var passphrase string
	if passphrase, err = readPassword(); err != nil {
		return err
	}

	var originalData []byte
	if originalData, err = ioutil.ReadFile(filename); err != nil {
		return err
	}

	var encryptedData []byte
	if encryptedData, err = encryptData(originalData, passphrase); err != nil {
		return err
	}

	if err = ioutil.WriteFile(filename, encryptedData, 0644); err != nil {
		return err
	}

	return nil
}

func decryptFile(filename string) (err error) {
	var passphrase string
	if passphrase, err = readPassword(); err != nil {
		return err
	}

	var encryptedData []byte
	if encryptedData, err = ioutil.ReadFile(filename); err != nil {
		return err
	}

	var originalData []byte
	if originalData, err = decryptData(encryptedData, passphrase); err != nil {
		return err
	}

	if err = ioutil.WriteFile(filename, originalData, 0644); err != nil {
		return err
	}

	return nil
}

func readPassword() (pwd string, err error){
	fmt.Print("Enter Password: ")

	var bytePassword []byte
	if bytePassword, err = terminal.ReadPassword(syscall.Stdin); err != nil {
		return pwd, fmt.Errorf("error reading password: %s", err.Error())
	}

	return string(bytePassword), nil
}

func init() {
	flag.StringVar(&fileFlag, "f", "", fmt.Sprintf("%-8s Filename (./path/yourfile.txt)", "string"))

	flag.BoolVar(&encryptFlag, "e", false, fmt.Sprintf("%-8s Encrypt", ""))
	flag.BoolVar(&decryptFlag, "d", false, fmt.Sprintf("%-8s Decrypt", ""))

	flag.Usage = func() {
		fmt.Printf("\nUsage: vcrypt -[OPTION] [ARGUMENTS...]\nParamiters:\n")
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("  -%-6s %s\n", f.Name, f.Usage)
		})

		os.Exit(ExitOk)
	}
}

func main() {
	var err error
	flag.Parse()

	if decryptFlag {
		err = decryptFile(fileFlag)
	} else if encryptFlag {
		err = encryptFile(fileFlag)
	}

	if err != nil {
		fmt.Printf("vcrypt error: %s", err.Error())
		os.Exit(ExitError)
	}

	os.Exit(ExitOk)
}