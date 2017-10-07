# Crypto_XOR

- Various XOR decoder techniques

## Background

- Problems solved based on CTF.

## Function Breakdown

### hex_xor(hex_a, hex_b)
- XOR 2 STRING HEX OF EQUAL LENGTH

- :param hex_a: equal length string hex
- :param hex_b: equal length string hex

- :return string hex XOR of a ^ b less the 0x

### char_xor(char_a, char_b)
- XOR 2 CHARS

- :param char_a: character
- :param char_b: character

- :return char of a^b

### single_key_xor(hex_string, char_key):
- XOR hexadecimal string with a single character using function xor()

- :param hex_string: string hexadecimal
- :param char_key: character

- :return character of each xor hex_string ^ char_key

## Problem Breakdowns
*see code for more details*

### ctf1-2
- trivial, no coding needed

### ctf3
- XOR Two Given Strings

### ctf4
- Decrypt given ciphertext (in hex), and xor with single unknown character

### ctf5
- Decrypt file with single unknown character and locate plaintext

### ctf6
- Decrypt ciphertext with repeating xor

### ctf7
- Decrypt base64 encoded file which has been encrypted with AES