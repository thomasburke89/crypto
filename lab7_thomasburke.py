"""lab7_template.py: Contains template to lab #7."""

import sys
import binascii
import array
import hashlib
import hmac
import base64
from Crypto.Cipher import AES
from Crypto import Random
# pip install pycrypto #things that don't work for 500, please.
# 30 hours later...
# pip install pycryptodome #winnerwinner
# pycharm > file > settings > project > + beside interpreter > pycryptodome

__author__ 	= "YOUR_NAME"
__license__ = "GPL"
__version__ = "1.0.1"
__date__ 	= "TODAY'S DATE"

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

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


def sign(k, m):
	"""Signs a message with HMAC-SHA-256 algorithm.
	Args:
		k (byte array): Byte array of signing key.
		m (byte array): Message to be signed with the key.
	Returns:
        byte array: Array of message's hash signature.
	"""

	m = bytes_to_string(m)
	h = hmac.new(k, m.encode("utf-8"), hashlib.sha256)
	dig = h.digest()

	return dig
	pass


def verify(k, h, m):
	"""Verifies HMAC-SHA-256 signature on a message.
	Args:
		k (byte array): Byte array of signing key.
		h (byte array): Hash signature being challenged.
		m (byte array): Message signed with the key.
	Returns:
        bool: True is signature computes; False otherwise.
	"""
	m = bytes_to_string(m)
	m = m.encode("utf-8")
	hash = hmac.new(k, m, hashlib.sha256)
	dig = hash.digest()
	return hmac.compare_digest(dig, h)

	pass


def encrypt(m, k1, k2):
	"""Encrypts a message with AES-128 algorithm.
	Args:
		m (byte array): Message to be encrypted.
		k1 (byte array): Byte array of AES key.
		k2 (byte array): Byte array of SHA key.
	Returns:
        byte array: H(iv + c) + iv + c, where: iv - initialization vector for
			encryption; H - authenticated hash signature of ciphertext;
			c - ciphertext from encryption.
	"""

	m = bytes_to_string(m)
	#m = pad(m)
	m = m.encode("utf-8")
	print(m)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(k1, AES.MODE_CBC, iv)
	data = base64.b64encode(iv + cipher.encrypt(m))
	print(data)
	print(type(data))
	encryption = hmac.new(k2, data, hashlib.sha256).digest()
	print(encryption)
	print(type(encryption))
	print(data + encryption)
	return data + encryption
	pass


def decrypt(c, k1, k2):
	"""Decrypts a ciphertext with AES-128 algorithm.
	Args:
		c (byte array): Ciphertext to be decrypted.
		k1 (byte array): Byte array of AES key.
		k2 (byte array): Byte array of SHA key.
	Returns:
        byte array: byte array of decrypted plaintext.
	"""
	c = base64.b64encode(c)
	iv = c[:16]
	hmac = c[-32:]
	cipher_text = c[16:-32]
	#verified_hmac = verify(k2, sign(sha_key, pt_bytes), pt_bytes)
	#if verified_hmac:
	cipher = AES.new(k1, AES.MODE_CBC, iv)
	print("Decrypted text:", cipher.decrypt(cipher_text))
	decodedbytes = cipher.decrypt(cipher_text)
	print(decodedbytes)
	return cipher.decrypt(cipher_text)
	#else:
		#return "Not Verified"
	pass


def main(argv):
	"""Main function of the script.
	Args:
		argv (list): Contains command-line arguments passed to the script.
	Returns:
        int: Error code after execution (0 if OK).
	"""
	error_code = 0
	pt = '16ish characters and some hoopla'
	aes_key = b'03b1d45002ddd3c2b29ee39e846a6d1f'
	sha_key = b'd43d9c00a8cf711791d60576f93170c78da08fc84261dfa5837b0da90bdfbb55'
	ct = b'4aadc1df26ee77f027667cb7655d98db4d998573a765395a4e01c3033855325ccd365a11a937ef01640cc401ec7359e2131d307d0b54e32cbfb068c8c2d026b751db89829c283c26f4af62450be34e4fcdfa5cdfd27e82927f9371eea9825edabacda21b45951d323b71a66d9ae17a837d7bf9675068e5fb8122220f3db01f5e90bcfa4b86ac2a334766a50ff7295ba88da19a2cc6cbda5e84652ed088370f85e460ef4862c4c5bfcf339379425786fbfa644f2c02e0ed8682f971cb1f22817212c7610542b0bc456087c82651315c3e91e9172b670ec7856f02077ba533c7923595b94b05e6075f980285288a8598615fd89b32e98ef581dde90beb91ae104084b24be4a2f393644b7e515cd5ba305d0d4d3c1a9cff3f8faa963abab72803e5'

	pt_bytes = string_to_bytes(pt)

	sign(sha_key, pt_bytes)
	verify(sha_key, sign(sha_key, pt_bytes), pt_bytes)
	encrypt(pt_bytes, aes_key, sha_key)
	decrypt(ct, aes_key, sha_key)
	return error_code


if __name__ == '__main__':
	error_code = main(sys.argv[1:])
	print('[+] Terminated with code: ' + str(error_code))
	sys.exit(error_code)