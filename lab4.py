"""lab4_template.py: Contains template to lab #4."""

import sys
import binascii
import array

__author__ 	= "Thomas Burke"
__license__ = "GPL"
__version__ = "1.0.1"
__date__ 	= "6/14/20"

CIPHERTEXT = '7d37997a7a45fd6652398374674afa321e019868284ce8655b78956f674fec7d1e2c9f782872e0745b36926f6d04ea7a4e30926f2604c17c4e3d91686448f03f1e3991696d56a97b5f2e9e736f04eb61513392732850e1761e1b96787b45fb336d309e7b7c04ea7a4e30926f2404fd7b5b78b8736d09dd7a533dda4d6940a97057289f787a04fe7a4a30d7766d5da9615b2d84782404e87d5a7899727f04fd7b5b78a1746f41e7764c3dd77e6154e1764c74d7646751a97b5f2e923d6746fa764c2e92792842e0614d2c9f7c6640a9721e2e926f7104e07e4e378569694afd334e2a986d6d56fd6a1e37913d614afa765d2d85782847fb6a4e2c983d7b47e176533d84332866ec705f2d84782841ff764c21d76e614aee7f5b789b7c6643fc72593dd7746604fd7b5b7880727a48ed335639843d6150fa335a318469614aea671e3492697c41fb3e582a926c7d41e770477884746f4ae8674b2a9231284dfd33572bd76b6d56f03e483d8564284ce8615a7891727a04e8335a3d83787a49e07d572b83746b04ea7a4e30926f2850e6335c3dd76e6d47fc615b78df787047ec634a3198737b04ec6b572b83312857fc705678966e286bdd431e2f9e696004e8334d31997a6441a9785b21d7687b41a03d1e19843d644be7741e39843d6904fa70563d9a78284dfa335037833d7a45e77751359e676d40a533523d83696d56a9754c3d86686d4aea6a1e3983696947e2601e3b96732845e5645f21843d6a41a9704c3991696d40a97259399e737b50a97a4a74d7686450e07e5f2c92717104fb764d2d9b69614aee335736d7747c57a9775b359e6e6d0a'
CLEN = len(CIPHERTEXT)
print(CLEN)
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


def modified_vigenere(m, k):
	"""Encrypts a plaintext message with a modified Vigenere cipher using XOR
		as opposed to modular addition.
	Args:
		m (list): Array of plaintext message bytes to be encrypted.
		k (list): Array of key bytes.
	Returns:
		str: hex-encoded ciphertext string.
	"""
	ciphertext = []
	for i in range(0, len(m), 1):
		ciphertext.append(m[i] ^ k[i % len(k)])
	return bytes_to_hex(ciphertext)


def comp_freq_sum(length):
	"""Given potential key length, computes the sum of byte frequencies over
		a ciphertext encrypted with modified Vigenere cipher.
	Args:
		length (int): Potential key length to compute sum of byte frequencies for.
	Returns:
		float: sum of byte frequencies for the given key length.
	"""

	### if supposed key length were to be 5 ###
	### for reference '7d37997a7a 45fd665239 8374674afa 321e019868' ###
	cipherbytes = len(CIPHERTEXT) / 2
	bucketnumber = cipherbytes / length
	print("Key length:", length)
	print("Number of Buckets:", bucketnumber)
	#### double the '+number' because 2 characters is a byte ####
	splitcipher = [CIPHERTEXT[i:i + (length * 2)] for i in range(0, len(CIPHERTEXT), (length * 2))]
	print("This is your split ciphertext:", splitcipher)
	### put splits into list so we can call indexes from each list ###
	cipherbuckets = []
	for i in splitcipher:
		cipherbuckets.append([i[j:j + 2] for j in range(0, len(i), 2)])
		print(i)
	## confirm cipher buckets are what we expected ###
	print("List of split ciphers:", cipherbuckets)
	### return particular bytes and add them to a list ###
	byte0 = []
	byte1 = []
	byte2 = []
	byte3 = []
	byte4 = []
	byte5 = []
	byte6 = []
	byte7 = []
	byte8 = []
	byte9 = []
	byte10 = []
	byte11 = []
	byte12 = []
	byte13 = []
	byte14 = []
	cipherbuckets[74].append("00")
	cipherbuckets[74].append("00")
	print("**************", cipherbuckets)
	for i in cipherbuckets:
		byte0.append(i[0])
		byte1.append(i[1])
		byte2.append(i[2])
		byte3.append(i[3])
		byte4.append(i[4])
		byte5.append(i[5])
		byte6.append(i[6])
		byte7.append(i[7])
	print("byte0:", byte0)
	freq0 = {f: byte0.count(f) for f in set(byte0)}
	freq1 = {f: byte1.count(f) for f in set(byte1)}
	freq2 = {f: byte2.count(f) for f in set(byte2)}
	freq3 = {f: byte3.count(f) for f in set(byte3)}
	freq4 = {f: byte4.count(f) for f in set(byte4)}
	freq5 = {f: byte5.count(f) for f in set(byte5)}
	freq6 = {f: byte6.count(f) for f in set(byte6)}
	freq7 = {f: byte7.count(f) for f in set(byte7)}
	print("freq0:", freq0)
	print(freq1)
	print(freq2)
	print(freq3)
	print(freq4)
	print(freq5)
	print(freq6)
	print(freq7)
	freq0squared = {key: pow(value/75, 2) for key, value in freq0.items()}
	freq0test    = {key: pow(value/75, 2) for key, value in freq0.items( )}
	freq1squared = {key: pow(value/75, 2) for key, value in freq1.items()}
	freq2squared = {key: pow(value/75, 2) for key, value in freq2.items()}
	freq3squared = {key: pow(value/75, 2) for key, value in freq3.items()}
	freq4squared = {key: pow(value/75, 2) for key, value in freq4.items()}
	freq5squared = {key: pow(value/75, 2) for key, value in freq5.items()}
	freq6squared = {key: pow(value/74, 2) for key, value in freq6.items()}
	freq7squared = {key: pow(value/74, 2) for key, value in freq7.items()}
	print("freq0test:", freq0test)
	print("freq0squared:", freq0squared)
	sum0 = sum(freq0squared.values())
	sum1 = sum(freq1squared.values())
	sum2 = sum(freq2squared.values())
	sum3 = sum(freq3squared.values())
	sum4 = sum(freq4squared.values())
	sum5 = sum(freq5squared.values())
	sum6 = sum(freq6squared.values())
	sum7 = sum(freq7squared.values())
	print("1:", sum0)
	print("2:", sum1)
	print("3:", sum2)
	print("4:", sum3)
	print("5:", sum4)
	print("6:", sum5)
	print("7:", sum6)
	print("8:", sum7)
	total = sum0 + sum1 + sum2 + sum3 + sum4 + sum5 + sum6 + sum7
	print("total:", float(total))

	return float(total)

	pass


def main(argv):
	"""Main function of the script.
	Args:
		argv (list): Contains command-line arguments passed to the script.
	Returns:
		int: Error code after execution (0 if OK).
	"""
	error_code = 0
	comp_freq_sum(8)

	return error_code


if __name__ == '__main__':
	error_code = main(sys.argv[1:])
	print('[+] Terminated with code: ' + str(error_code))
	sys.exit(error_code)