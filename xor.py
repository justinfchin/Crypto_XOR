"""
Author: Justin F. Chin

Purpose: Various XOR Functions for Encrypt/Decrypt
 
"""

import string  # for ascii letters (alphabet)
import binascii  # for converting strings to hex

""" BUILT-IN FUNCTION UNDERSTANDING

int(_,16):  converts string hex to int ascii
hex()[2:]:  converts int ascii to string hex less the 0x
ord():      converts int char to int ascii
chr():      converts int ascii to char
^:          xor two int ascii

"""


def hex_xor(hex_a, hex_b):
    """ XOR 2 STRING HEX OF EQUAL LENGTH
    
    :param hex_a: equal length string hex
    :param hex_b: equal length string hex
    
    :return string hex XOR of a ^ b less the 0x
    
    """
    return hex(int(hex_a, 16) ^ int(hex_b, 16))[2:]


def char_xor(char_a, char_b):
    """ XOR 2 CHARS
    
    :param char_a: character
    :param char_b: character
    
    :return char of a^b
    
    """
    return chr(ord(char_a) ^ ord(char_b))


def ctf3():
    """ XOR THE TWO STRINGS """
    a = '42696c6c792c20646f6e27'
    b = '742062652061206865726f'
    print(hex_xor(a,b))


def single_key_xor(hex_string, char_key):
    """ XOR hexadecimal string with a single character using function xor()
    
    :param hex_string: string hexadecimal
    :param char_key: character
    
    :return character of each xor hex_string ^ char_key
    
    """
    # Declare Variables
    decryption = ''  # for holding decrypted text

    #  Iterate through the length of hex_string, xor each pair with the hex of the char_key
    # converting the result to int ascii then chr and storing that in the variable
    for i in range(0,len(hex_string)-1, 2):
        decryption += chr(int(hex_xor(hex_string[i]+hex_string[i+1], hex(ord(char_key))), 16))
    return decryption


def ctf4():
    """ DECRYPT STRING WHICH IS ENCRYPTED WITH SINGLE CHAR XOR """
    # Cipher Text, CT
    ct = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    # Run for entire character list / aka printable list
    for char in string.printable:
        print("Attempt:"+char+": ", single_key_xor(ct, char))


def points(input_line):
    """ SUM THE TOTAL AMT OF LETTERS IN INPUT WITH VALUES BASED ON FREQUENCY

    Source: Frequencies obtained from wiki 
    https://en.wikipedia.org/wiki/Letter_frequency
    """
    total = 0
    freq = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
        'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
        'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
        'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
        'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
        'z': 0.00074
    }

    for letter in input_line:
        if letter in freq:
            total += freq[letter]

    return total


def ctf5():
    """ DECRYPT FILE WHICH IS ENCRYPTED WITH SINGLE CHAR XOR """

    # Open File
    with open('ctf5ct.txt') as ct_file:
        # Separate Line by Line
        ct = set(line.strip() for line in ct_file)

    # Define Variables
    all_points = {}  # to keep score of all the lines in an empty dictionary

    # For each line
    for line in ct:
        for char in string.printable:
            # Decrypt the line
            decryption = single_key_xor(line, char)
            # Save the points, line, & char used for decryption of each line
            all_points[decryption] = [points(decryption), line, char]
    # Sort the lines by points from largest to smallest
    all_points = sorted(all_points.items(), key=lambda x: x[1][0], reverse=True)
    # Print top 5 items
    print(all_points[:5])


def repeating_xor(hex_string, string_key):
    """ 
    :param hex_string: a hex string
    :param string_key: just a char string 
    
    :return hex_string^string_key
    """
    # Declare Variables

    new_key = ''  # for holding repeated key

    # Repeat key in new_key for as long as hex_string is
    for i in range(0, round(len(hex_string)/2), 1):
        new_key += hex(ord(string_key[i % len(string_key)]))[2:]

    # Perform xor on both hex
    xor_result = hex_xor(hex_string, new_key)
    decryption = ''

    # Convert the hex to char
    for j in range(0, len(xor_result)-1, 2):
        decryption += chr(int(xor_result[j]+xor_result[j+1], 16))

    return decryption


def ctf6():
    """ DECRYPT REPEATING XOR """
    # Cipher Text
    ct = '7d2e03292f3370267435262277363b2c2328233c3b2f33'
    key = 'WUTANG'
    print(repeating_xor(ct, key))


def ctf7():
    """ DECRYPT BASE64 ENCODED FILE WHICH IS ENCRYPTED WITH AES """
