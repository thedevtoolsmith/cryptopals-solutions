// Implement repeating key XOR

package main

import (
	"encoding/hex"
	"fmt"
)

func encodeToHex(ip string) []byte {
	op := make([]byte, hex.EncodedLen(len(ip)))
	hex.Encode(op, []byte(ip))
	return op
}

func repeatingKeyXor(plaintext []byte, key []byte) []byte {
	op := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		op[i] = plaintext[i] ^ key[i%len(key)]
	}
	fmt.Print(len(op))
	return op
}

func main() {
	input := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	ciphertext := repeatingKeyXor([]byte(input), []byte(key))
	fmt.Print(input, "=> ", string(encodeToHex(string(ciphertext))))
}
