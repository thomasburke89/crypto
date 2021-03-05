"""lab5_template.py: Contains template to lab #5."""

import sys
import binascii
import array
import math

__author__ 	= "YOUR_NAME"
__license__ = "GPL"
__version__ = "1.0.1"
__date__ 	= "TODAY'S DATE"

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

	cipherbytes = len(CIPHERTEXT) / 2
	#### double the '+number' because 2 characters is a byte ####
	splitcipher = [CIPHERTEXT[i:i + (length * 2)] for i in range(0, len(CIPHERTEXT), (length * 2))]
	### put splits into list so we can call indexes from each list ###
	cipherbuckets = []
	for i in splitcipher:
		cipherbuckets.append([i[j:j + 2] for j in range(0, len(i), 2)])
	### return particular bytes and add them to a list ###
	byte0 = []
	byte1 = []
	byte2 = []
	byte3 = []
	byte4 = []
	byte5 = []
	byte6 = []
	byte7 = []
	cipherbuckets[74].append("00")
	cipherbuckets[74].append("00")
	for i in cipherbuckets:
		byte0.append(i[0])
		byte1.append(i[1])
		byte2.append(i[2])
		byte3.append(i[3])
		byte4.append(i[4])
		byte5.append(i[5])
		byte6.append(i[6])
		byte7.append(i[7])
	freq0 = {f: byte0.count(f) for f in set(byte0)}
	freq1 = {f: byte1.count(f) for f in set(byte1)}
	freq2 = {f: byte2.count(f) for f in set(byte2)}
	freq3 = {f: byte3.count(f) for f in set(byte3)}
	freq4 = {f: byte4.count(f) for f in set(byte4)}
	freq5 = {f: byte5.count(f) for f in set(byte5)}
	freq6 = {f: byte6.count(f) for f in set(byte6)}
	freq7 = {f: byte7.count(f) for f in set(byte7)}
	freq0squared = {key: pow(value / cipherbytes, 2) for key, value in freq0.items()}
	freq1squared = {key: pow(value / cipherbytes, 2) for key, value in freq1.items()}
	freq2squared = {key: pow(value / cipherbytes, 2) for key, value in freq2.items()}
	freq3squared = {key: pow(value / cipherbytes, 2) for key, value in freq3.items()}
	freq4squared = {key: pow(value / cipherbytes, 2) for key, value in freq4.items()}
	freq5squared = {key: pow(value / cipherbytes, 2) for key, value in freq5.items()}
	freq6squared = {key: pow(value / cipherbytes, 2) for key, value in freq6.items()}
	freq7squared = {key: pow(value / cipherbytes, 2) for key, value in freq7.items()}
	sum0 = sum(freq0squared.values())
	sum1 = sum(freq1squared.values())
	sum2 = sum(freq2squared.values())
	sum3 = sum(freq3squared.values())
	sum4 = sum(freq4squared.values())
	sum5 = sum(freq5squared.values())
	sum6 = sum(freq6squared.values())
	sum7 = sum(freq7squared.values())
	total = sum0 + sum1 + sum2 + sum3 + sum4 + sum5 + sum6 + sum7

	return float(total)
	pass


def get_lower_letter_freq(b):
	"""Looks up average character frequency for a lower-case letter in English.
	Args:
		b (byte): Byte of lower-case letter [a-z] to look up.
	Returns:
		float: average frequency of the given lower-case letter in English text.
	"""
	if b == 97:
		return 0.08167
	elif b == 98:
		return 0.01492
	elif b == 99:
		return 0.02782
	elif b == 100:
		return 0.04253
	elif b == 101:
		return 0.12702
	elif b == 102:
		return 0.02228
	elif b == 103:
		return 0.02015
	elif b == 104:
		return 0.06094
	elif b == 105:
		return 0.06966
	elif b == 106:
		return 0.00153
	elif b == 107:
		return 0.00772
	elif b == 108:
		return 0.04025
	elif b == 109:
		return 0.02406
	elif b == 110:
		return 0.06749
	elif b == 111:
		return 0.07507
	elif b == 112:
		return 0.01929
	elif b == 113:
		return 0.00095
	elif b == 114:
		return 0.05987
	elif b == 115:
		return 0.06327
	elif b == 116:
		return 0.09056
	elif b == 117:
		return 0.02758
	elif b == 118:
		return 0.00978
	elif b == 119:
		return 0.02361
	elif b == 120:
		return 0.00150
	elif b == 121:
		return 0.01974
	elif b == 122:
		return 0.00074
	else:
		return 0.0


def crack_vigenere_key(length):
	"""Recovers the complete key that was used in the modified Vigenere cipher.
	Args:
		length (int): Length of the key to be cracked.
	Returns:
		str: Hex-encoded string of the recovered key.
	"""
	print("crack vigenere key length:", length)
	### round the number up so the key is at least as long as the ciphertext ###
	iterations = math.ceil(length/8)
	key = '3ea2a3a4c1c2c364' #>
	repeatKey = key*iterations
	print("ct :", CIPHERTEXT)
	print("key:", repeatKey)

	"""split ciphertext into lists like above
	split key into similar list
	check for every xor'd byte for each array to land between 32 and 126 (first letter between 65 and 90?) 
	Find the byte that maximizes the sum of qipi2 for each position.
	repeat 3 and 4"""

	#### double the '+number' because 2 characters is a byte ####
	splitcipher = [CIPHERTEXT[i:i + (8 * 2)] for i in range(0, len(CIPHERTEXT), (8 * 2))]
	splitkey = [repeatKey[i:i + (8 * 2)] for i in range(0, len(repeatKey), (8 * 2))]
	print("This is your split ciphertext:", splitcipher)
	### put splits into list so we can call indexes from each list ###
	cipherbuckets = []
	keybuckets = []
	for i in splitcipher:
		cipherbuckets.append([i[j:j + 2] for j in range(0, len(i), 2)])
		#print(i)
	for i in splitkey:
		keybuckets.append([i[j:j + 2] for j in range(0, len(i), 2)])
	## confirm cipher buckets are what we expected ###
	print("List of split ciphers:", cipherbuckets)
	print("List of split keyssss:", keybuckets)
	### return particular bytes and add them to a list ###
	cbyte0 = []
	cbyte1 = []
	cbyte2 = []
	cbyte3 = []
	cbyte4 = []
	cbyte5 = []
	cbyte6 = []
	cbyte7 = []
	kbyte0 = []
	kbyte1 = []
	kbyte2 = []
	kbyte3 = []
	kbyte4 = []
	kbyte5 = []
	kbyte6 = []
	kbyte7 = []
	cipherbuckets[74].append("00")
	cipherbuckets[74].append("00")
	for i in cipherbuckets:
		cbyte0.append(i[0])
		cbyte1.append(i[1])
		cbyte2.append(i[2])
		cbyte3.append(i[3])
		cbyte4.append(i[4])
		cbyte5.append(i[5])
		cbyte6.append(i[6])
		cbyte7.append(i[7])
	print("cbyte0", cbyte0)
	cbyte00 = [int(x, 16) for x in cbyte0]
	cbyte01 = [int(x, 16) for x in cbyte1]
	cbyte02 = [int(x, 16) for x in cbyte2]
	cbyte03 = [int(x, 16) for x in cbyte3]
	cbyte04 = [int(x, 16) for x in cbyte4]
	cbyte05 = [int(x, 16) for x in cbyte5]
	cbyte06 = [int(x, 16) for x in cbyte6]
	cbyte07 = [int(x, 16) for x in cbyte7]
	print("cbyte00", cbyte00)
	"""Your computer can execute over a billion instructions per second, and it is no
trouble to try every possible byte (0-255) for a given ith byte of the key."""
	cbyteanswer=[]
	#while not all(32 <= i <= 126 for i in cbyte02):
	rangelist = range(255)
	"""for i in cbyte02:
		for j in rangelist:
			while not all(32 <= i <= 126 for i in cbyte02):
				print(i ^ rangelist[j])
				if all(32 <= i <= 126 for i in cbyte02):
					print("maybe the answer", cbyte02)"""
	for i in keybuckets:
		kbyte0.append(i[0])
		kbyte1.append(i[1])
		kbyte2.append(i[2])
		kbyte3.append(i[3])
		kbyte4.append(i[4])
		kbyte5.append(i[5])
		kbyte6.append(i[6])
		kbyte7.append(i[7])
	print("kbyte0", kbyte0)
	kbyte00 = [int(x, 16) for x in kbyte0]
	print("kbyte00", kbyte00)

	xorbyte = bytes(a ^ b for (a, b) in zip(cbyte00, kbyte00))
	#cant xor these and hextobytes makes tiny lists?
	print(bytes_to_string(xorbyte))
	return repeatKey

	pass


def decrypt_modified_vigenere(c, k):
	"""Decrypts the modified version of the Vigenere cipher with proper key.
	Args:
		c (list): Array of ciphertext bytes to be decrypted.
		k (list): Array of key bytes.
	Returns:
		str: ASCII plaintext message string.
	"""
	print("c:", c)
	print("k:", k)
	xorbytes = bytes(a ^ b for (a, b) in zip(c, k))
	xorstring = bytes_to_string(xorbytes)
	print(xorstring)
	return xorstring
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
	decrypt_modified_vigenere(hex_to_bytes(CIPHERTEXT), hex_to_bytes(crack_vigenere_key(CLEN/2)))
	return error_code


if __name__ == '__main__':
	error_code = main(sys.argv[1:])
	print('[+] Terminated with code: ' + str(error_code))
	sys.exit(error_code)