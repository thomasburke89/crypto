"""lab2_template.py: Contains template to lab #2."""

import sys
import binascii
import array

__author__ 	= "Thomas Burke"
__license__ = "GPL"
__version__ = "1.0.1"
__date__ 	= "5/31/2020"

CIPHER_1 =		'e028b758f93266f9ad6e' #20... 10 characters w/ 2 per character
CIPHER_2 =		'e169a75cf0252ce4e143'
CIPHER_3 =		'fc21b113cc3228e7e81a'
CIPHER_4 =		'f126a113ff212fe4e24e'
CIPHER_5 =		'fc21b113da2f33e9e81a'
CIPHER_6 =		'fc21b113d92e28ede05b'
CIPHER_7 =		'e23cb85ae93361c9ec5f'
CIPHER_8 =		'eb3bad43e82f2de5ea43'
CIPHER_9 =		'e228a252bc2932aaec1a'
CIPHER_10 =		'e528ad13e82824aacb55'
TARGET_CIPHER =	'ff2cb85fbc242ee4e81b'

ct1 = '1f94d62da72cbba86f7bc661c4cacad438dbef1ce7bfeaed1f5f4c1cbff7510267'
ct2 = '0399cd3ba732ada8737fc370c4d8c1d538d6e40da2ebe1eb061d5a0bf1ec5a092a5c80'
ct3 = '0593c87ef32dadfa7e39c635d599c2d53edbaf'
ct4 = '0593cb37e420e8e0746995618cdcd69a2dd2ed5ff1ebe5ea061d5e07ebf01f06695acf990e7f20b5a55766d3681ef9c0'
ct5 = '1c93d02aa66582fd686a957a8adc8fd723cce45fe8eaf7ec525f4c0dfeed4c0267'

def string_to_hex(s):
	"""Converts ASCII string to hexadecimal string.
		Example: "Hello, world!" should return "48656c6c6f2c20776f726c6421"
	Args:
		s (string): Given ASCII string.
	Returns:
        string: Equivalent hexadecimal string.
	"""
	return str(binascii.hexlify(str.encode(s)))[2:-1]


def hex_to_string(h):
	"""Converts hexadecimal string to ASCII string.
		Example: "48656c6c6f2c20776f726c6421" should return  "Hello, world!"
	Args:
		h (string): Given hexadecimal string.
	Returns:
        string: Equivalent ASCII string.
	"""
	return bytes.fromhex(h).decode('utf-8')

def hex_to_bytes(h):
	"""Converts hexadecimal string to array of bytes.
		Example: "48656c6c6f2c20776f726c6421" should return [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]
	Args:
		h (string): Given hexadecimal string.
	Returns:
        string: Equivalent array of integer bytes.
	"""
	hex_bytes = bytes.fromhex(h)
	b = []
	for byte in hex_bytes:
		b.append(byte)
	return b

def bytes_to_hex(b):
	"""Converts byte array to hexadecimal string.
		Example: [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33] should return "48656c6c6f2c20776f726c6421"
	Args:
		b (byte array): Given byte array.
	Returns:
        string: Equivalent hexadecimal string.
	"""
	byte_array = array.array('B',b).tobytes()
	return byte_array.hex()

def string_to_bytes(s):
	"""Converts ASCII string to byte array.
		Example: "Hello, world!" should return {72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33}
	Args:
		s (string): Given ASCII string.
	Returns:
        array: Equivalent array of integer bytes.
	"""
	ba = str.encode(s)
	b = []
	for byte in ba:
		b.append(byte)
	return b

def bytes_to_string(b):
	"""Converts byte array to ASCII string.
		Example: [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33] should return "Hello, world!"
	Args:
		b (byte array): Given byte array.
	Returns:
        string: Equivalent ASCII string.
	"""
	s = ''
	for byte in b:
		s += chr(byte)
	return s

def otp_encrypt(m, k):
	"""Encrypts an array of message bytes by XORing them with key bytes.
	Args:
		m (list): Array of plaintext message bytes to be encrypted with One-Time-Pad.
		k (list): Array of key bytes.
	Returns:
        list: Array of ciphertext bytes.
	"""
	return [a ^ b for a, b in zip(m, k)]

def print_messages(k):
	"""Prints out the entire state of all potential plaintext messages given
		the current state of the key, regardless of message lengths or the
		current key length.
	Args:
		k (list): Array of key bytes.
	"""

	key = '4bfcbf5e8745c8881b1eb515e4b9afba4cbe817f829f8498723d296e9f983f674939aee9670b41d9853b03a71c7b8bee'
	#pt1 = bytes_to_string(otp_encrypt(hex_to_bytes(ct1), hex_to_bytes(key)))
	#ptb1 = otp_encrypt(hex_to_bytes(ct1), hex_to_bytes(key))
	print('Message #1: ' + pt1)
	print('Message #2: ' + bytes_to_string(otp_encrypt(hex_to_bytes(ct2), hex_to_bytes(key))))
	print('Message #3: ' + bytes_to_string(otp_encrypt(hex_to_bytes(ct3), hex_to_bytes(key))))
	print('Message #4: ' + bytes_to_string(otp_encrypt(hex_to_bytes(ct4), hex_to_bytes(key))))
	print('Message #5: ' + bytes_to_string(otp_encrypt(hex_to_bytes(ct5), hex_to_bytes(key))))
	#print(pt1[1])
	#print(ptb1[1])
	pass

    key = '4bfcbf5e8745c8881b1eb515e4b9afba4cbe817f829f8498723d296e9f983f674939aee9670b41d9853b03a71c7b8bee'
    print(print_messages(key))

	pass

def is_possible_key_byte(pos, k, min, max):
	"""Checks whether a given key byte at a certain position is within required
		parameters for ALL messages.
	Args:
		pos (int): byte position, starting at 0.
		k  (byte): potential key byte to check for validity.
		min (int): the maximum value for the plain message byte after XOR with the potential key byte.
		max (int): the maximum value for the plain message byte after XOR with the potential key byte.
	Returns:
        bool: true if the potential key byte is within parameters; false otherwise.
	"""
	"""key = '4bfcbf5e8745c8881b1eb515e4b9afba4cbe817f829f8498723d296e9f983f674939aee9670b41d9853b03a71c7b8bee'
	pos = 1
	min = 32
	max = 126"""

	ptbytes = otp_encrypt(hex_to_bytes(ct1), hex_to_bytes(k))

	if ptbytes[pos] >= min and ptbytes[pos] <= max:
		print(ptbytes[pos])
		return True
	else:
		return False

	pass

def check_key_against_message(m, pos, c):
	"""Given a guess of the cryptanalyst on what the next character of a 
		decrypted plaintext message should be, attempts to fit a potential key
		byte so that the character is resolved.
	Args:
		m   (int): message/ciphertext identifier to check against.
		pos (int): byte position, starting at 0.
		c  (char): character/byte to fit the potential key byte to according to the cryptanalyst's guess.
	Returns:
        byte: fitting potential key byte if successful; the NUL byte otherwise.
	"""
	m1 = 'This is test sentence number one.'
	m1 = string_to_bytes(m1)
	pos = 2
	pos= m1[pos]
	c = 'a'
	print(pos,c)
	xored = pos^string_to_bytes(c)
	print(c)
	#xored = m1[pos] ^ c
	print(xored)


	pass

def main(argv):
	"""Main function of the script.
	Args:
		argv (list): Contains command-line arguments passed to the script.
	Returns:
        int: Error code after execution (0 if OK).
	"""
	error_code = 0
	
	key = '4bfcbf5e8745c8881b1eb515e4b9afba4cbe817f829f8498723d296e9f983f674939aee9670b41d9853b03a71c7b8bee'
	m1 = 'This is test sentence number one.'
	m2 = 'Here we have another test sentence.'
	m3 = "Now there's 1 more."
	m4 = 'Notice how they all start with a capital letter.'
	m5 = 'Woot! Just one more just because.'
	print('Ciphertext #1: ' + bytes_to_hex(otp_encrypt(string_to_bytes(m1), hex_to_bytes(key))))
	print('Ciphertext #2: ' + bytes_to_hex(otp_encrypt(string_to_bytes(m2), hex_to_bytes(key))))
	print('Ciphertext #3: ' + bytes_to_hex(otp_encrypt(string_to_bytes(m3), hex_to_bytes(key))))
	print('Ciphertext #4: ' + bytes_to_hex(otp_encrypt(string_to_bytes(m4), hex_to_bytes(key))))
	print('Ciphertext #5: ' + bytes_to_hex(otp_encrypt(string_to_bytes(m5), hex_to_bytes(key))))
	print(hex_to_bytes(key))
	return error_code

if __name__ == '__main__':
	error_code = main(sys.argv[1:])
	print('[+] Terminated with code: ' + str(error_code))
	sys.exit(error_code)