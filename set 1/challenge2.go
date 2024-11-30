// Get two hex encoded strings
// Xor one against the other
// The result should be a hex

package main

import (
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

func encodeToHex(ip string) []byte {
	op := make([]byte, hex.EncodedLen(len(ip)))
	hex.Encode(op, []byte(ip))
	return op
}

func xor(op1 []byte, op2 []byte) []byte {
	op := make([]byte, len(op1))
	for i := 0; i < len(op1); i++ {
		op[i] = op1[i] ^ op2[i]
	}
	return op
}

func main() {
	inp1 := "1c0111001f010100061a024b53535009181c"
	hex1 := decodeHex(inp1)
	inp2 := "686974207468652062756c6c277320657965"
	hex2 := decodeHex(inp2)
	res := xor(hex1, hex2)
	fmt.Print(string(encodeToHex(string(res))))
}
