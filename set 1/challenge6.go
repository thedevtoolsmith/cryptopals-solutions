// Implement repeating key XOR

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

var input64 = `HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS
BgBHVBwNRU0HBAxTEjwMHghJGgkRTxRMIRpHKwAFHUdZEQQJAGQmB1MANxYG
DBoXQR0BUlQwXwAgEwoFR08SSAhFTmU+Fgk4RQYFCBpGB08fWXh+amI2DB0P
QQ1IBlUaGwAdQnQEHgFJGgkRAlJ6f0kASDoAGhNJGk9FSA8dDVMEOgFSGQEL
QRMGAEwxX1NiFQYHCQdUCxdBFBZJeTM1CxsBBQ9GB08dTnhOSCdSBAcMRVhI
CEEATyBUCHQLHRlJAgAOFlwAUjBpZR9JAgJUAAELB04CEFMBJhAVTQIHAh9P
G054MGk2UgoBCVQGBwlTTgIQUwg7EAYFSQ8PEE87ADpfRyscSWQzT1QCEFMa
TwUWEXQMBk0PAg4DQ1JMPU4ALwtJDQhOFw0VVB1PDhxFXigLTRkBEgcKVVN4
Tk9iBgELR1MdDAAAFwoFHww6Ql5NLgFBIg4cSTRWQWI1Bk9HKn47CE8BGwFT
QjcEBx4MThUcDgYHKxpUKhdJGQZZVCFFVwcDBVMHMUV4LAcKQR0JUlk3TwAm
HQdJEwATARNFTg5JFwQ5C15NHQYEGk94dzBDADsdHE4UVBUaDE5JTwgHRTkA
Umc6AUETCgYAN1xGYlUKDxJTEUgsAA0ABwcXOwlSGQELQQcbE0c9GioWGgwc
AgcHSAtPTgsAABY9C1VNCAINGxgXRHgwaWUfSQcJABkRRU8ZAUkDDTUWF01j
OgkRTxVJKlZJJwFJHQYADUgRSAsWSR8KIgBSAAxOABoLUlQwW1RiGxpOCEtU
YiROCk8gUwY1C1IJCAACEU8QRSxORTBSHQYGTlQJC1lOBAAXRTpCUh0FDxhU
ZXhzLFtHJ1JbTkoNVDEAQU4bARZFOwsXTRAPRlQYE042WwAuGxoaAk5UHAoA
ZCYdVBZ0ChQLSQMYVAcXQTwaUy1SBQsTAAAAAAAMCggHRSQJExRJGgkGAAdH
MBoqER1JJ0dDFQZFRhsBAlMMIEUHHUkPDxBPH0EzXwArBkkdCFUaDEVHAQAN
U29lSEBAWk44G09fDXhxTi0RAk4ITlQbCk0LTx4cCjBFeCsGHEETAB1EeFZV
IRlFTi4AGAEORU4CEFMXPBwfCBpOAAAdHUMxVVUxUmM9ElARGgZBAg4PAQQz
DB4EGhoIFwoKUDFbTCsWBg0OTwEbRSonSARTBDpFFwsPCwIATxNOPBpUKhMd
Th5PAUgGQQBPCxYRdG87TQoPD1QbE0s9GkFiFAUXR0cdGgkADwENUwg1DhdN
AQsTVBgXVHYaKkg7TgNHTB0DAAA9DgQACjpFX0BJPQAZHB1OeE5PYjYMAg5M
FQBFKjoHDAEAcxZSAwZOBREBC0k2HQxiKwYbR0MVBkVUHBZJBwp0DRMDDk5r
NhoGACFVVWUeBU4MRREYRVQcFgAdQnQRHU0OCxVUAgsAK05ZLhdJZChWERpF
QQALSRwTMRdeTRkcABcbG0M9Gk0jGQwdR1ARGgNFDRtJeSchEVIDBhpBHQlS
WTdPBzAXSQ9HTBsJA0UcQUl5bw0KB0oFAkETCgYANlVXKhcbC0sAGgdFUAIO
ChZJdAsdTR0HDBFDUk43GkcrAAUdRyonBwpOTkJEUyo8RR8USSkOEENSSDdX
RSAdDRdLAA0HEAAeHQYRBDYJC00MDxVUZSFQOV1IJwYdB0dXHRwNAA9PGgMK
OwtTTSoBDBFPHU54W04mUhoPHgAdHEQAZGU/OjV6RSQMBwcNGA5SaTtfADsX
GUJHWREYSQAnSARTBjsIGwNOTgkVHRYANFNLJ1IIThVIHQYKAGQmBwcKLAwR
DB0HDxNPAU94Q083UhoaBkcTDRcAAgYCFkU1RQUEBwFBfjwdAChPTikBSR0T
TwRIEVIXBgcURTULFk0OBxMYTwFUN0oAIQAQBwkHVGIzQQAGBR8EdCwRCEkH
ElQcF0w0U05lUggAAwANBxAAHgoGAwkxRRMfDE4DARYbTn8aKmUxCBsURVQf
DVlOGwEWRTIXFwwCHUEVHRcAMlVDKRsHSUdMHQMAAC0dCAkcdCIeGAxOazkA
BEk2HQAjHA1OAFIbBxNJAEhJBxctDBwKSRoOVBwbTj8aQS4dBwlHKjUECQAa
BxscEDMNUhkBC0ETBxdULFUAJQAGARFJGk9FVAYGGlMNMRcXTRoBDxNPeG43
TQA7HRxJFUVUCQhBFAoNUwctRQYFDE43PT9SUDdJUydcSWRtcwANFVAHAU5T
FjtFGgwbCkEYBhlFeFsABRcbAwZOVCYEWgdPYyARNRcGAQwKQRYWUlQwXwAg
ExoLFAAcARFUBwFOUwImCgcDDU5rIAcXUj0dU2IcBk4TUh0YFUkASEkcC3QI
GwMMQkE9SB8AMk9TNlIOCxNUHQZCAAoAHh1FXjYCDBsFABkOBkk7FgALVQRO
D0EaDwxOSU8dGgI8EVIBAAUEVA5SRjlUQTYbCk5teRsdRVQcDhkDADBFHwhJ
AQ8XClJBNl4AC1IdBghVEwARABoHCAdFXjwdGEkDCBMHBgAwW1YnUgAaRyon
B0VTGgoZUwE7EhxNCAAFVAMXTjwaTSdSEAESUlQNBFJOZU5LXHQMHE0EF0EA
Bh9FeRp5LQdFTkAZREgMU04CEFMcMQQAQ0lkay0ABwcqXwA1FwgFAk4dBkIA
CA4aB0l0PD1MSQ8PEE87ADtbTmIGDAILAB0cRSo3ABwBRTYKFhROHUETCgZU
MVQHYhoGGksABwdJAB0ASTpFNwQcTRoDBBgDUkksGioRHUkKCE5THEVCC08E
EgF0BBwJSQoOGkgGADpfADETDU5tBzcJEFMLTx0bAHQJCx8ADRJUDRdMN1RH
YgYGTi5jMURFeQEaSRAEOkURDAUCQRkKUmQ5XgBIKwYbQFIRSBVJGgwBGgtz
RRNNDwcVWE8BT3hJVCcCSQwGQx9IBE4KTwwdASEXF01jIgQATwZIPRpXKwYK
BkdEGwsRTxxDSToGMUlSCQZOFRwKUkQ5VEMnUh0BR0MBGgAAZDwGUwY7CBdN
HB5BFwMdUz0aQSwWSQoITlMcRUILTxoCEDUXF01jNw4BTwVBNlRBYhAIGhNM
EUgIRU5CRFMkOhwGBAQLTVQOHFkvUkUwF0lkbXkbHUVUBgAcFA0gRQYFCBpB
PU8FQSsaVycTAkJHYhsRSQAXABxUFzFFFggICkEDHR1OPxoqER1JDQhNEUgK
TkJPDAUAJhwQAg0XQRUBFgArU04lUh0GDlNUGwpOCU9jeTY1HFJARE4xGA4L
ACxSQTZSDxsJSw1ICFUdBgpTNjUcXk0OAUEDBxtUPRpCLQtFTgBPVB8NSRoK
SREKLUUVAklkERgOCwAsUkE2Ug8bCUsNSAhVHQYKUyI7RQUFABoEVA0dWXQa
Ry1SHgYOVBFIB08XQ0kUCnRvPgwQTgUbGBwAOVREYhAGAQBJEUgETgpPGR8E
LUUGBQgaQRIaHEshGk03AQANR1QdBAkAFwAcUwE9AFxNY2QxGA4LACxSQTZS
DxsJSw1ICFUdBgpTJjsIF00GAE1ULB1NPRpPLF5JAgJUVAUAAAYKCAFFXjUe
DBBOFRwOBgA+T04pC0kDElMdC0VXBgYdFkU2CgtNEAEUVBwTWXhTVG5SGg8e
AB0cRSo+AwgKRSANExlJCBQaBAsANU9TKxFJL0dMHRwRTAtPBRwQMAAATQcB
FlRlIkw5QwA2GggaR0YBBg5ZTgIcAAw3SVIaAQcVEU8QTyEaYy0fDE4ITlhI
Jk8DCkkcC3hFMQIEC0EbAVIqCFZBO1IdBgZUVA4QTgUWSR4QJwwRTWM=
`

func encodeToHex(ip string) []byte {
	op := make([]byte, hex.EncodedLen(len(ip)))
	hex.Encode(op, []byte(ip))
	return op
}

func decodeBase64(ip string) []byte {
	op := make([]byte, base64.StdEncoding.DecodedLen(len(ip)))
	base64.StdEncoding.Decode(op, []byte(ip))
	return op
}

func hammingDistance(ip1 []byte, ip2 []byte) int {
	hDistance := 0
	if len(ip1) != len(ip2) {
		lenDiff := math.Abs(float64((len(ip1) - len(ip2))))
		if len(ip1) > len(ip2) {
			for i := 0; i < int(lenDiff); i++ {
				ip2 = append(ip2, 0)
			}
		} else {
			for i := 0; i < int(lenDiff); i++ {
				ip1 = append(ip1, 0)
			}
		}
	}

	numberOf1sinBinary := func(num int) int {
		count := 0
		for tmp := num; tmp != 0; {
			tmp = tmp & (tmp - 1)
			count++
		}
		return count
	}

	for i := range len(ip1) {
		xor := ip1[i] ^ ip2[i]
		count := numberOf1sinBinary(int(xor))
		hDistance += count
	}
	return hDistance
}

func getMinKeys(m map[int]float64, n int) []int {
	// This is to make it work with the sort.Slice function
	type kv struct {
		Key   int
		Value float64
	}
	var pairs []kv

	// Populate the slice with key-value pairs from the map
	for k, v := range m {
		pairs = append(pairs, kv{Key: k, Value: v})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Value == pairs[j].Value {
			return pairs[i].Key < pairs[j].Key // Break ties by key
		}
		return pairs[i].Value < pairs[j].Value // Sort by value
	})

	// Extract the first n keys
	result := []int{}
	for i := 0; i < len(pairs) && i < n; i++ {
		result = append(result, pairs[i].Key)
	}

	return result
}

func calculateNormEditDistance(ciphertext []byte, keySize float64) float64 {
	numOfBlocks := len(ciphertext) / int(keySize)
	var nBlocks = make([][]byte, numOfBlocks)
	var hDistances []float64
	normalisedHammingDistance := 0.0

	for i := range numOfBlocks {
		if (i*int(keySize))+int(keySize) > len(ciphertext) {
			tmp := ciphertext[i*int(keySize):]
			for j := 0; j < i*int(keySize)+int(keySize)-len(ciphertext); j++ {
				tmp = append(tmp, 0)
				nBlocks[i] = tmp
			}
		} else {
			nBlocks[i] = ciphertext[i*int(keySize) : (i*int(keySize))+int(keySize)]
		}
	}

	for i := range numOfBlocks {
		for j := range numOfBlocks {
			hDist := hammingDistance(nBlocks[i], nBlocks[j])
			hDistf := float64(hDist) / keySize
			hDistances = append(hDistances, hDistf)
		}
	}

	for _, i := range hDistances {
		normalisedHammingDistance += i
	}
	normalisedHammingDistance = normalisedHammingDistance / float64(len(hDistances))

	return normalisedHammingDistance
}

func transposeBlock(ciphertext []byte, keySize int) [][]byte {
	transposedBlocks := make([][]byte, keySize)

	for i, b := range ciphertext {
		transposedBlocks[i%keySize] = append(transposedBlocks[i%keySize], b)
	}
	return transposedBlocks
}

func xor(op1 []byte, op2 []byte) []byte {
	op := make([]byte, len(op1))
	for i := 0; i < len(op1); i++ {
		op[i] = op1[i] ^ op2[i]
	}
	return op
}

func legitAnswerProbability(inp string) float64 {
	var characterFrequency = map[string]float64{
		"a": 0.0651738, "b": 0.0124248, "c": 0.0217339, "d": 0.0349835, "e": 0.1041442, "f": 0.0197881, "g": 0.0158610,
		"h": 0.0492888, "i": 0.0558094, "j": 0.0009033, "k": 0.0050529, "l": 0.0331490, "m": 0.0202124, "n": 0.0564513,
		"o": 0.0596302, "p": 0.0137645, "q": 0.0008606, "r": 0.0497563, "s": 0.0515760, "t": 0.0729357, "u": 0.0225134,
		"v": 0.0082903, "w": 0.0171272, "x": 0.0013692, "y": 0.0145984, "z": 0.0007836, " ": 0.1918182}

	score := 0.0
	for _, c := range inp {
		s := strings.ToLower(string(c))
		score += characterFrequency[s]
	}
	return score
}

func decryptSingleKeyXor(inp []byte) byte {
	hex2 := make([]byte, len(inp))
	highest_ratio := 0.0
	// var legitAnswer, key string
	var key byte
	for i := 0; i <= 255; i++ {
		for j := 0; j < len(inp); j++ {
			hex2[j] = byte(i)
		}
		res := xor(inp, hex2)
		stringRatio := legitAnswerProbability(string(res))

		if highest_ratio <= stringRatio {
			highest_ratio = stringRatio
			// legitAnswer = string(res)
			key = byte(i)
		}
	}
	// fmt.Print(legitAnswer, "\n")
	return key
}

func repeatingKeyXor(plaintext []byte, key []byte) []byte {
	op := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		op[i] = plaintext[i] ^ key[i%len(key)]
	}
	return op
}

func decodeHex(ip string) []byte {
	op := make([]byte, hex.DecodedLen(len(ip)))
	_, err := hex.Decode(op, []byte(ip))
	if err != nil {
		fmt.Print(err)
	}
	return op
}

func main() {
	bruteforcedResults := map[int]float64{}
	input := decodeBase64(input64)
	for keysize := 2; keysize <= 40; keysize++ {
		nDist := calculateNormEditDistance(input, float64(keysize))
		fmt.Print(keysize, ":", nDist, "\n")
		bruteforcedResults[keysize] = nDist
	}

	candidateKeys := getMinKeys(bruteforcedResults, 1)
	fmt.Print(candidateKeys)

	for _, keySize := range candidateKeys {
		transposedBlocks := transposeBlock(input, keySize)
		var key []byte
		for _, block := range transposedBlocks {
			k := decryptSingleKeyXor(block)
			key = append(key, k)
		}
		fmt.Print("Key=", string(key), "\n")

		fmt.Print(string(repeatingKeyXor(input, key)), "\n")
	}
}
