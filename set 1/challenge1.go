// Convert hex to base64
// Operate on raw bytes

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func decodeHex(ip string) []byte {
	op := make([]byte, hex.DecodedLen(len(ip)))
	_, err := hex.Decode(op, []byte(ip))
	if err != nil {
		fmt.Print(err)
	}
	return op
}

func encodeToBase64(ip string) []byte {
	op := make([]byte, base64.StdEncoding.EncodedLen(len(ip)))
	base64.StdEncoding.Encode(op, []byte(ip))
	return op
}

func main() {
	inp := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	fmt.Print(string(encodeToBase64(string(decodeHex(string(inp))))))
}
