# Crypto_XOR
> Various XOR decoder techniques to solve Capture the Flag (CTF) Problems

# Problem Breakdowns
*see code for more details*

### ctf1-2
- trivial, no coding needed

### ctf3
- Problem:
    - XOR Two Given Strings return output
    - a = '42696c6c792c20646f6e27'                                
    - b = '742062652061206865726f' 
- Idea:
    1. convert strings hex to int ascii which is base 16
        - so that we can use the ^ operator
    2. perform the ^ operation
    3. convert the result back to hex

### ctf4
- Problem:
    - Decrypt given ciphertext (in hex) which is encrypted with single char xor
    - ct = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
- Idea: 
    1. iterate through the length of the ciphertext and xor each pair of hex with a single char 
        - for each pair, specifically, we convert the hex result to int ascii then chr and concatenate that result with all the others, hopefully, providing us with something readable 
        - for the single char, we loop through all the characters in string.printable

### ctf5
- Problem:
    - Decrypt file with single unknown character and locate plaintext
- Idea:
    1. open the file
    2. separate each line and put it in a set data structure to remove duplicates and add randomness to the order (this helps with searching) 
    3. for each of the line we xor the pair of hex with each char in string.printable, giving us the decrypted text
        - we also derive a points system to add to each decrypted text
            - the reason for this point system is that we want to assign the decrypted text the highest number of points the more likely hood that it contains words from the English dictionary
            - from [wikipedia](https://en.wikipedia.org/wiki/Letter_frequency), we obtain letter frequencies
            - to calculate the points, we sum together the corresponding frequency of the letter according to what we received from wikipedia
        - we then store the decrypted text as a key in a dictionary with its associated value as a list of points assigned to the decryption, the cipher text, and the char used to xor the line. 
    5. we then sort the dictionary by highest points and print the top 5 points
        - one of these top five should have a readable phrase 

### ctf6
- Problem:
    - Decrypt ciphertext with repeating xori
    - ct = '7d2e03292f3370267435262277363b2c2328233c3b2f33'
- Idea:
    1. some digging led the key to be 'WUTANG' 
    2. create a new key to fit the length of the cipher text
        - note that there should be a letter per two chars in the cipher text since it is in hexadecimal
    3. perform the xor operation
    4. convert the returned result to char

# Function Breakdown

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

- Decrypt base64 encoded file which has been encrypted with AES

### points(input_line):
- Sum the total amount of letters in input with values based on frequency

- :param input_line: string

- :return total based on summing the letter frequency based on the English language

### repeating_xor(hex_string, string_key):
- XOR hexadecimal string with repeated string_key

- :param hex_string: string hexadecimal
- :param string_key: string

- :return xor of hex_string with repeated string_key

