"""lab6_template.py: Contains template to lab #6."""

import sys
import binascii
import array
import urllib.request

__author__ 	= "YOUR_NAME"
__license__ = "GPL"
__version__ = "1.0.1"
__date__ 	= "TODAY'S DATE"


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
	byte_array = array.array('B', b).tobytes()
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


def padding_oracle(c):
	"""Attempts to decrypt a ciphertext with AES-256 cipher, CBC crypto mode,
		and PKCS7 padding scheme.
	Args:
		c (str): ciphertext in hexadecimal string format.
	Returns:
		bool: True if decryption was successful; False otherwise.
	"""
	resp = ''
	with urllib.request.urlopen('http://msudakov.net/sbu/crypto/paddingOracle?cipher=' + c) as response:
		resp = response.read().decode("utf-8")
	if resp == '1':
		return True
	else:
		return False


def main(argv):
	"""Main function of the script.
	Args:
		argv (list): Contains command-line arguments passed to the script.
	Returns:
		int: Error code after execution (0 if OK).
	"""
	error_code = 0
	scanlist = [*range(0, 256, 1)]
	ciphertext = '289ae9f358fea214f1fb90887c4c9f89a07aba41d4efa99394a08cea97a02e98'
	mct =        '289ae9f358fea214f1fbb08a7e4e9d8ba07aba41d4efa99394a08cea97a02e98'
	bytecipher = hex_to_bytes(ciphertext)
	modifiedbytecipher = hex_to_bytes(mct)
	print(bytecipher)

	"""print(padding_oracle('3030303030303030303030887c4c9f89a07aba41d4efa99394a08cea97a02e98'))
	                                    broke here ^ on byte 12, last 5 bytes are being checked
	last 5 bytes of encoded data should be 0x0505050505
	"""
	iv = int('7', 16)
	print("iv:", iv)
	print(type(iv))
	splitcipher = [ciphertext[i:i + (16 * 2)] for i in range(0, len(ciphertext), (16 * 2))]
	print("This is your split ciphertext:", splitcipher)
	# put splits into list so we can call indexes from each list
	cipherbuckets = []
	for i in splitcipher:
		cipherbuckets.append([i[j:j + 2] for j in range(0, len(i), 2)])
		print(i)
	# confirm cipher buckets are what we expected
	#print("List of split ciphers:", cipherbuckets)
	for x in scanlist:
		modifiedbytecipher[9] = x
		"""print(modifiedbytecipher)
		print(bytes_to_hex(modifiedbytecipher))"""
		mbc = bytes_to_hex(modifiedbytecipher)
		if padding_oracle(mbc):
			print("winner", x, mbc)
			print(bytes_to_hex(x))

	plaintext = "!"
	return error_code


if __name__ == '__main__':
	error_code = main(sys.argv[1:])
	print('[+] Terminated with code: ' + str(error_code))
	sys.exit(error_code)