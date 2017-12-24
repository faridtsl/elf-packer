from struct import unpack, pack
from sys import argv
from ELF import *
from utilities import *


def main(filename):
	with open(filename, "rb") as f:
		elf = f.read()
		elf_array = bytearray(elf)

	"""
		Elf64_Addr 		8		Unsigned program address		Q
		Elf64_Off		8		Unsigned file offset			Q
		Elf64_Half		2		Unsigned medium integer			H
		Elf64_Word		4		Unsigned integer				I
		Elf64_Sword		4		Signed integer					i
		Elf64_Xword		8		Unsigned long integer			Q
		Elf64_Sxword	8		Signed long integer				q
		unsigned char	1		Unsigned small integer			c
	"""

	parsed_elf = ELF(elf)
#	print parsed_elf
#	print hex(len(elf_array))
	emb = bytearray("A"*0x40)
	parsed_elf.embed(emb, argv[1] + ".pdf")
	
"""
	## Pack
	elf_array = write_c_string(elf_array, ".packed")
	packed_str = len(elf) - sh_offset
	packed_section = text_section
	packed_section.sh_name = packed_str
	packed = bytearray(elf)
	packed = write_c_string(packed, ".packed")

	#for i in xrange(text_size):
	#	packed[text_offset + i] ^= 0x5a
	
	ep = len(packed)
	packed.append(0xcc)
	print "%#x" % ep
	packed[24 : 24 + 8] = bytearray(pack("Q",ep))
	
	with open(argv[1] + ".packed", "wb") as f:
		f.write(packed)
"""

if __name__ == "__main__":
	main(argv[1])


