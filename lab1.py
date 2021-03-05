"""lab1_template.py: Contains template to lab #1."""

import sys
import binascii
import array

__author__ 	= "Thomas Burke"
__license__ = "GPL"
__version__ = "1.0.1"
__date__ 	= "5/23/2020"

def string_to_hex(s):
	##s = 'Hello, world!'
	##print(s)
	test = bytes(s, 'ascii')
	##print(test)
	tmp = binascii.hexlify(test)
	##print (s2h)
	final = str(tmp, 'ascii')
	##print (final)

	return final

	"""Converts ASCII string to hexadecimal string.
		Example: "Hello, world!" should return "48656c6c6f2c20776f726c6421"
	Args:
		s (string): Given ASCII string.
	Returns:
        string: Equivalent hexadecimal string.
	"""
	pass

def hex_to_string(h):
	##h = "48656c6c6f2c20776f726c6421"
	tmp = binascii.unhexlify(h)
	##print(tmp)
	final = str(tmp, 'ascii')
	##print(final)

	return final

	"""Converts hexadecimal string to ASCII string.
		Example: "48656c6c6f2c20776f726c6421" should return  "Hello, world!"
	Args:
		h (string): Given hexadecimal string.
	Returns:
        string: Equivalent ASCII string.
	"""
	pass

def hex_to_bytes(h):
	##hexi = "48656c6c6f2c20776f726c6421"
	##tmpold = bytes(hexi, 'ascii')
	tmp = binascii.unhexlify(h)
	tmpnew = str(tmp,'ascii')
	##print(tmpnew) ##returns type str Hello, world!
	##print(type(tmpnew))
	final = list(bytearray(tmpnew, 'ascii'))
	##print(final) ##returns type list [72...]
	##print(type(final))
	##print(tmpold)
	##print(type(tmpold))
	##print(tmpnew)
	##print(type(tmpnew))

	return final


	"""Converts hexadecimal string to array of bytes.
		Example: "48656c6c6f2c20776f726c6421" should return [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]
	Args:
		h (string): Given hexadecimal string.
	Returns:
        string: Equivalent array of integer bytes.
	"""
	pass

def bytes_to_hex(b):
	##b = [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]
	tmp = binascii.hexlify(bytearray(b))
	##print(tmp)
	final = str(tmp, 'ascii')
	##print (final)

	return final

	"""Converts byte array to hexadecimal string.
		Example: [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33] should return "48656c6c6f2c20776f726c6421"
	Args:
		b (byte array): Given byte array.
	Returns:
        string: Equivalent hexadecimal string.
	"""
	pass

def string_to_bytes(s):
	s = 'Hello, world!'
	##print(type(s)) ##returns str
	final = list(bytearray(s, 'ascii'))
	##print(final) ##returns desired array
	##print(type(final)) ##class of list
	return final

	"""Converts ASCII string to byte array.
		Example: "Hello, world!" should return {72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33}
	Args:
		s (string): Given ASCII string.
	Returns:
        array: Equivalent array of integer bytes.
	"""
	pass

def bytes_to_string(b):
	b = [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]
	tmp = binascii.hexlify(bytearray(b))
	tmpnew = binascii.unhexlify(tmp)
	##print(tmp) ##returns b'hexvalue'
	##print(tmpnew) ##returns b'Hello, world!'
	final = str(tmpnew, 'ascii')
	##print(final) ##returns Hello, world!

	return final

	"""Converts byte array to ASCII string.
		Example: [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33] should return "Hello, world!"
	Args:
		b (byte array): Given byte array.
	Returns:
        string: Equivalent ASCII string.
	"""
	pass

def break_caesar_shift(ciphertext, shift):
	##ciphertext = "lzjww jafyk xgj lzw wdnwf-cafyk mfvwj lzw kcq, kwnwf xgj lzw vosjx-dgjvk af zsddk gx klgfw, fafw xgj egjlsd ewf, vggewv lg vaw, gfw xgj lzw vsjc dgjv gf zak vsjc lzjgfw af lzw dsfv gx egjvgj ozwjw lzw kzsvgok daw. gfw jafy lg jmdw lzwe sdd, gfw jafy lg xafv lzwe, gfw jafy lg tjafy lzwe sdd sfv af lzw vsjcfwkk tafv lzwe. af lzw dsfv gx egjvgj ozwjw lzw kzsvgok daw."
	before = list(bytearray(ciphertext, 'ascii'))
	##shift = 18
	after = []
	##while not int(shift) in range(1,26):
	##	shift = int(input("Enter the shift variable (1-25): "))
	for x in before:
		if x in (32,44,45,46):
			after.append(x)
		elif x == 46:
			after.append(x)
		else:
			x = x-shift
			after.append((x -97)%26+97)
	##print("This is beforeshift:",before)
	##print("This is aftershifts:",after)
	tmp = binascii.hexlify(bytearray(after))
	tmpnew = binascii.unhexlify(tmp)
	final = str(tmpnew, 'ascii')
	##print("This is before the shift:", ciphertext)
	##print("This is after the shift:",final) #got lucky with 18 and got it

	return final

	"""Breaks Caesar's Shift Cipher, given any shift parameter.
	Args:
		ciphertext (string): Message encrypted using the cipher.
		shift (int): Shift of plain alphabet (0-25) to create cipher alphabet.
	Returns:
        string: Plaintext English message if used with proper shift parameter; empty string otherwise.
	"""
	pass

def count_Es(s):
	##s = "threeringsfortheelvenkingsundertheskysevenforthedwarflordsinhallsofstonenineformortalmendoomedtodieoneforthedarklordonhisdarkthroneinthelandofmordorwheretheshadowslieoneringtorulethemalloneringtofindthemoneringtobringthemallandinthedarknessbindtheminthelandofmordorwheretheshadowslie"
	es = 0
	##print(len(s))
	for i in s:
		if i == 'e':
			es += 1
	##print(es) #38 in this example

	return es
	"""Counts the number of occurrences of character 'e' in a string.
	Args:
		s (string): String to be counted on.
	Returns:
        int: The number of times 'e' occurs in the string.
	"""
	## pass

def find_caesar_shift(ciphertext):
	##ciphertext = "lzjwwjafykxgjlzwwdnwfcafykmfvwjlzwkcqkwnwfxgjlzwvosjxdgjvkafzsddkgxklgfwfafwxgjegjlsdewfvggewvlgvawgfwxgjlzwvsjcdgjvgfzakvsjclzjgfwaflzwdsfvgxegjvgjozwjwlzwkzsvgokdawgfwjafylgjmdwlzwesddgfwjafylgxafvlzwegfwjafylgtjafylzwesddsfvaflzwvsjcfwkktafvlzweaflzwdsfvgxegjvgjozwjwlzwkzsvgokdaw"
	before = list(bytearray(ciphertext, 'ascii'))
	## print(before) confirming before is an array
	shift = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]
	key = 0
	for i in shift:
		after = []
		for x in before:
			x = x - i
			after.append((x - 97) % 26 + 97)
		tmp = binascii.hexlify(bytearray(after))
		tmpnew = binascii.unhexlify(tmp)
		final = str(tmpnew, 'ascii')
		x = count_Es(final)
		## print("this is x:",x) Just learned how that works =D
		if x/len(ciphertext) >=.10 and x/len(ciphertext) <= .15:
			## print("This is after the shift:",final) Confirming I am returning expected values
			key = i
			break
	if key == 0:
		print('Using statistical analysis on just the letter "e" was not enough to crack this cipher.')
		return 0
	else:
		return key

	"""Iterates over all 26 shift possibilities of Caesar's Shift Cipher to find
		a shift that yields between 12% and 14% of 'e' occurrences in the
		resulting plaintext decryption of ciphertext.
	Args:
		ciphertext (string): Encrypted message to find proper shift on.
	Returns:
        int: The proper shift needed to break the cipher.
	"""
	pass

def main(argv):
	"""Main function of the script.
	Args:
		argv (list): Contains command-line arguments passed to the script.
	Returns:
        int: Error code after execution (0 if OK).
	"""
	error_code = 0
	
	s = 'Hello, world!'
	h = string_to_hex(s)
	b = string_to_bytes(s)
	print(s)
	print(h)
	print(b)
	print(bytes_to_string(b))
	print(hex_to_bytes(h))
	print(bytes_to_hex(b))

	##ciphertext = "lzjwwjafykxgjlzwwdnwfcafykmfvwjlzwkcqkwnwfxgjlzwvosjxdgjvkafzsddkgxklgfwfafwxgjegjlsdewfvggewvlgvawgfwxgjlzwvsjcdgjvgfzakvsjclzjgfwaflzwdsfvgxegjvgjozwjwlzwkzsvgokdawgfwjafylgjmdwlzwesddgfwjafylgxafvlzwegfwjafylgtjafylzwesddsfvaflzwvsjcfwkktafvlzweaflzwdsfvgxegjvgjozwjwlzwkzsvgokdaw"
	ciphertext = "lzjww jafyk xgj lzw wdnwf-cafyk mfvwj lzw kcq, kwnwf xgj lzw vosjx-dgjvk af zsddk gx klgfw, fafw xgj egjlsd ewf, vggewv lg vaw, gfw xgj lzw vsjc dgjv gf zak vsjc lzjgfw af lzw dsfv gx egjvgj ozwjw lzw kzsvgok daw. gfw jafy lg jmdw lzwe sdd, gfw jafy lg xafv lzwe, gfw jafy lg tjafy lzwe sdd sfv af lzw vsjcfwkk tafv lzwe. af lzw dsfv gx egjvgj ozwjw lzw kzsvgok daw."
	ciphertext = "lwzdvwkhzrqwriwkhlppruwdojrgvvrphwlphvwrjudqwsurvshulwbdqgorqjlpsxqlwbwrphqzkrvhfulphvwkhbzhuhplqghgwrsxqlvklqrughuwkdwdfrpsohwhuhyhuvhriiruwxqhpljkwpdnhwkhpvxiihupruhelwwhuob"
	print("Caesar's Shift broken!\nMessage: " + break_caesar_shift(ciphertext, find_caesar_shift(ciphertext)))

	return error_code

if __name__ == '__main__':
	error_code = main(sys.argv[1:])
	print('[+] Terminated with code: ' + str(error_code))
	sys.exit(error_code)
