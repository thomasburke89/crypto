"""lab3_template.py: Contains template to lab #3."""

import sys
import binascii
import array

__author__	= "Thomas Burke"
__license__ = "GPL"
__version__ = "1.0.1"
__date__	= "6/7/2020"

CIPHER_1 = 'e028b758f93266f9ad6e5044b9bd2d1fd709cfc965fe286dc1fe241b5a1e5b30a6c7dad04efe223383de9e0647d8663e74da768747322b9e8d963fb7dcaea29595aa94b930be26d3cd78'
CIPHER_2 = 'e169a75cf0252ce4e143185ebcbc6c3f8211c29231aa0928d9b3691b594a0f38f3c8c79409f0213b8d'
CIPHER_3 = 'fc21b113cc3228e7e81a7c44b9bc6e39cb13cfd32cf96066d7aa69045c190f77b286dbd11abf213983c8840550d8733e44c123ce5a772fdadd8a39fbd1afa88496f3daec25f02d9dc97667f40a89e09c8a24042f85136eb3f231fffd98394d889a7bc7cd4cbc361ed6a4035782b180955c70fd0f0bac2ec1b3d7be918fc811ee4a75bd2ae1f222a0c06246576572834abbb12bd2a5e72a22fabc82cafd4b92408f484d293e4d6fadef4db82944c8e963113c9eb21a1b2536cfdbac9d4c6b4be215edf96768fd6828c0d12351e330e4eacff6a42dfc746a8cc8db8c7226ce2437b6d6de7cad6035f0f8a1585b0c29dd29619acfcadb7d2f7b8400cc10d92d5fcb07de9d4734b739e9ae1e42c71cf6e713641d68bfcab538a8ce03ac0b3224e25808b0bc'
CIPHER_4 =	'f126a113ff212fe4e24e185daaaa7e6c822c8a9228aa2128cbbb3b1848040f77bcc088c006fa6e0cc6d9830c418b1b777fd02f875e3e2b96c98722b7d1bae78096efd6aa28ff24d8883977b1399eaf8dcb762f2593472dbdf23abea9f0205f8f86279eb94cb8655ac7a4070181bcd2911b66fd0d47ed2ecae796b88687cf5dba5b7bbc26b6fc2bafc871034a233fb740a5b66b96c2e16434fead8f8ffb41c11490441912764d2baefd1feb504fd8bf651c3d80b80a1b363ecac1ee'
CIPHER_5 =	'fc21b113da2f33e9e81a515eebae652cd645cd9a33ef3328d9fe030b4d035b3fbad588c401e82b2d8d9ab81d12d87d7f639566c94c2529838d8439f2d2b8e7978cef97b821fa69dfd17670fd14d0ac96933f182dc61326b5f233a2f3f0194adc867ccc9f4ba82b5ad5f61952c7b4ce901b61f10f4eb932c4e7d3aad093d50aba4b60e968fff423bd85604b4065788348b1a03c96f1e12333eba681dda1'
CIPHER_6 =	'fc21b113d92e28ede05b1840aaba6524cc00d9d332ef326d98bf691d4c181232a086c7d24efa223ac0ce830618c6387d65d46dce4a3622dadf8d24f8ccfca49d8ee293be64f328dec03f7ff40bd0a49a93331a2596022afcfd3ab5fda5235b98d560d0cd50b5201ec3b71e4d9ef880805431f9084fe034d2f6d8ad9983d259ba4171a77ee3e83eeed17b035537709641b3ac65d5eae32933edad8dcee302c1049151552e734d3ba8e91eaa67448df26f113a9ab60c42663cd6dfad8158635cea0eeaba2928b20d2bc8c23a55b167edf698bfbd3ef5763e80c28f8b6572d3233cf3f59b7aa8602ff0f4a14b57102add2924b5dedb93653c22f701c1598b3b5edb548c994061af25ffae1a5ec61cf0ef45520073b2ccf916e9d84a9644'
CIPHER_7 =	'e23cb85ae93361c9ec5f4b4cb9f97a2cd145cbd317e52d69d6fe390145030f3eb0cfc9da42bf293acddf830859877d7f63d123c946232f98c18770f6cba8af9b8caa99aa64d228c9c13831e10a9fb39acb763e2fc61722bde531b5fdb1705d8e9c7dd78e45b1654cc9ba09018ebb80805374b4045da82ed1e096ad9887d211f64770e97ef9ba33a6c034474028769141f0b72396f1e62176cda189cee10eb30588545b2d774f6fa0e45aeb7d48c8bf7414208bf7115d662bd1d7e0a659675ee55ac6b8376fe02d6b'
CIPHER_8 =	'eb3bad43e82f2de5ea431844b8f97925c745da8124e93461dbbb690f470e5b24a7d3cccd4ef0287fd7df92015bc22c6b68c623c146256e89c88125e5dbfca49b93e783a22dfd28c9c1397fb1119ee08b8d33563a94023db9f237b4fdbf361e889d60cc8904ad244cd2bf0952c7b6c1985774f0414aa936c0e1c5b8828fc342b40259a678f3ba20abcb71514429739b08f0bb37cff5fa2b31edaf94c7f60e8813d8405b2e6b586fa2e550b87d52d8fc72143d89f71f55227fd8dca1984f7056e51da3a53569e62726cec92414e578edf198a6a12de67d249186db817520c36b29b2c08a61a07261bfe3ef58561b6fc82e6698c5ccdb763c6dc942db59983d5ec0408c884628ad2ceeeb5f5dc74fece802601c2f'
CIPHER_9 = 'e228a252bc2932aaec1a5f48a5bc7f2cce48da8637fa2f7bddfe2a01441a0e23b6d488c41cf0292dc2d79c005bcc7d726cdb64d248302bdad98a31e39eb5b4d49de598af31ec3bd8c6223db11b9ca18c967b142b95022af0bc3bb3b7b5334ad19a7bd7884aa9205a8af60d4f83f5d3845e72fd0742ae21c9ffcff99483d558fd4c71ad2ae2f567a6c4624605246cc242b5af65dfe8fe2833f2ab8adbee5a880f96015d246e4921a5ef50a86045debf670e739eb80d482f3dd5d7ee'
CIPHER_10 =	'e528ad13e82824aacb554a4eaef96f288212c3872daa3967cdf0'
TARGET_CIPHER = 'ff2cb85fbc242ee4e81b1864ebb1623dc745c49c32aa3967cdfe3a0b4c4a1338a486cdc20bf16e3e83ca941b53ce3e6a61cc23d44c343c9fd9c233e5c7acb39bdef995a421f32c9dce377dfd0bd0a18f8424026a850823acf031a5b8bc291e8b9d6cd0cd4db03552c3bb094f93b0c4d4527ff70e59bf25c6e7daa0dec6f454f74779ab6fe4ba33a6cc670d'



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
	bytesk = hex_to_bytes(k)

	"""print(hexk)
	print(type(hexk))"""

	print('Message #1: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_1), bytesk)))
	print('Message #2: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_2), bytesk)))
	print('Message #3: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_3), bytesk)))
	print('Message #4: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_4), bytesk)))
	print('Message #5: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_5), bytesk)))
	print('Message #6: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_6), bytesk)))
	print('Message #7: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_7), bytesk)))
	print('Message #8: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_8), bytesk)))
	print('Message #9: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_9), bytesk)))
	print('Message #10: ' + bytes_to_string(otp_encrypt(hex_to_bytes(CIPHER_10), bytesk)))
	print('Message TARGET: ' + bytes_to_string(otp_encrypt(hex_to_bytes(TARGET_CIPHER), bytesk)))

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

	list1 = (hex_to_bytes(CIPHER_1))
	list2 = (hex_to_bytes(CIPHER_2))
	list3 = (hex_to_bytes(CIPHER_3))
	list4 = (hex_to_bytes(CIPHER_4))
	list5 = (hex_to_bytes(CIPHER_5))
	list6 = (hex_to_bytes(CIPHER_6))
	list7 = (hex_to_bytes(CIPHER_7))
	list8 = (hex_to_bytes(CIPHER_8))
	list9 = (hex_to_bytes(CIPHER_9))
	list10 = (hex_to_bytes(CIPHER_10))
	listtarget = (hex_to_bytes(TARGET_CIPHER))
	#print(list1)
	#print(type(list1))
	listylist = [list1, list2, list3, list4, list5, list6, list7, list8, list9, list10, listtarget]
	#print(listylist)
	#print(type(listylist))
	#print('Number of elements in list: ', len(listylist))
	#print(listylist[0])
	#print("list 1: ", listylist[0][pos])
	#print(listylist[1])
	#print("list 2: ", listylist[1][pos])
	#print(listylist[2])
	#print("list 3: ", listylist[2][pos])
	bytek = hex_to_bytes(k)
	xorlist = []

	for i in listylist:
		#print("i[pos]: ", i[pos])
		#print("bytek: ", int(bytek[0]))
		xor = i[pos] ^ int(bytek[0])
		xorlist.append(xor)
		#print("xor: ", xor)
	print(xorlist)
	for i in xorlist:
		if not min <= i <= max:
			print('False')
			return False
	print('True')
	return True

	pass


def getcipher(x):
	return {
		1: CIPHER_1,
		2: CIPHER_2,
		3: CIPHER_3,
		4: CIPHER_4,
		5: CIPHER_5,
		6: CIPHER_6,
		7: CIPHER_7,
		8: CIPHER_8,
		9: CIPHER_9,
		10: CIPHER_10,
		11: TARGET_CIPHER,
	}.get(x, '')


def check_key_against_message(m, pos, c):
	"""Given a guess of the cryptanalyst on what the next character of a
		decrypted plaintext message should be, attempts to fit a potential key
		byte so that the character is resolved. Takes a decrypted "next guess" character
		and returns the corresponding key byte if it is successful.
	Args:
		m   (int): message/cipher-text identifier to check against.
		pos (int): byte position, starting at 0.
		c  (char): character/byte to fit the potential key byte to according to the cryptanalyst's guess.
	Returns:
		byte: fitting potential key byte if successful; the NUL byte otherwise.
	"""
	cipher = getcipher(m)
	bytecipher = hex_to_bytes(cipher)
	byteguess = string_to_bytes(c)
	samplelist = [*range(0, 256, 1)]
	xorlist = []
	for num in samplelist:
		xor = num ^ byteguess[0] # 0-255 xor'd with 51 to return
		if xor == bytecipher[pos]:
			print(xor)
	xor = bytecipher[pos] ^byteguess[0]
	xorlist.append(xor)
	returnbyte = bytes_to_hex(xorlist)

	return returnbyte

	pass


def main(argv):
	"""Main function of the script.
	Args:
		argv (list): Contains command-line arguments passed to the script.
	Returns:
		int: Error code after execution (0 if OK).
	"""
	KEY = 'a849d4339c40418a8d3a382dcbd90d4da265aaf3458a4008b8de496e296a7b57d3a6a8b46e9f4e5fa3baf16935ab5d1e0db503a729574efaade25097bedcc7f4fe8af6cc449e49bda856119178f0c0ffe556764ae6674edc9c54d1ddd0503efcf509beed24dd453ea6d66c21e7d5a0f43b1194612bcd40a593b6d9f0e6a6319a2214c90a969a47cea5142325451fe224d0d845'
	print_messages(KEY)
	is_possible_key_byte(3, '21', 32, 126)
	print("add this to key: ", check_key_against_message(4, 146, '.'))
	error_code = 0

	return error_code


if __name__ == '__main__':
	error_code = main(sys.argv[1:])
	print('[+] Terminated with code: ' + str(error_code))
	sys.exit(error_code)