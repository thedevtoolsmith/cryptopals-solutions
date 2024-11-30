// One character has been xored against a given string.
// Have to find out what that character is

package main

import (
	"encoding/hex"
	"fmt"
	"unicode"
)

func decodeHex(ip string) []byte {
	op := make([]byte, hex.DecodedLen(len(ip)))
	_, err := hex.Decode(op, []byte(ip))
	if err != nil {
		fmt.Print(err)
	}
	return op
}

func xor(op1 []byte, op2 []byte) []byte {
	op := make([]byte, len(op1))
	for i := 0; i < len(op1); i++ {
		op[i] = op1[i] ^ op2[i]
	}
	return op
}

func legitAnswerProbability(inp string) float64 {
	score := 0.0
	symbol := 0
	alphanum := 0

	for _, c := range inp {
		if unicode.IsLetter(c) {
			alphanum += 1
		} else {
			symbol += 1
		}
	}
	score = float64(alphanum) / float64(symbol)
	return score
}

func main() {
	allCharacters := "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	inp1 := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	hex1 := decodeHex(inp1)
	hex2 := make([]byte, len(hex1))
	highest_ratio := 0.0
	var legitAnswer, key string
	for i := 0; i < len(allCharacters); i++ {
		for j := 0; j < len(hex1); j++ {
			hex2[j] = allCharacters[i]
		}
		res := xor(hex1, hex2)
		stringRatio := legitAnswerProbability(string(res))
		if highest_ratio <= stringRatio {
			highest_ratio = stringRatio
			legitAnswer = string(res)
			key = string(allCharacters[i])
		}
	}
	fmt.Print(key, " : ", legitAnswer, " entropy:", highest_ratio, "\n")
	// fmt.Print(entropy([]byte("Cooking MC like a pound of bacon")))
	// fmt.Print(string(hex1))
	// fmt.Print(hex2)
	// res := xor(hex1, hex2)
	// fmt.Print(string(encodeToHex(string(res))))
}
