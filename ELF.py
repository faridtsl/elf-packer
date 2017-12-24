from struct import unpack, pack
from sys import argv
from utilities import *

"""
        Elf64_Addr      8       Unsigned program address        Q
        Elf64_Off       8       Unsigned file offset            Q
        Elf64_Half      2       Unsigned medium integer         H
        Elf64_Word      4       Unsigned integer                I
        Elf64_Sword     4       Signed integer                  i
        Elf64_Xword     8       Unsigned long integer           Q
        Elf64_Sxword    8       Signed long integer             q
        unsigned char   1       Unsigned small integer          c
"""

class ELF:

	class Elf64_Ehdr:
		def __init__(self, header_tuple = None, elf = None):
			"""
				e_ident			:		Identifies the file as an ELF object file.
				e_type			:		Identifies the object file type.
				e_machine		:		Identifies the target architecture.
				e_version		:		Identifies the version of the object file format.
				e_entry			:		Orginal entry point.
				e_phoff			:		Contains the file offset, in bytes, of the program header table.
				e_shoff			:		Contains the file offset, in bytes, of the section header table.
				e_flags			:		Contains processor-specific flags. 
				e_ehsize		:		Contains the size, in bytes, of the ELF header. 
				e_phentsize		:		Contains the size, in bytes, of a program header table entry. 
				e_phnum			:		Contains the number of entries in the program header table. 
				e_shentsize		:		Contains the size, in bytes, of a section header table entry. 
				e_shnum			:		Contains the number of entries in the section header table. 
				e_shstrndx		:		Contains the section header table index of the section containing the section name string table.
			"""
			if header_tuple == None:
				header_tuple = unpack("16sHHIQQQIHHHHHH", elf[:64])

			(
				self.e_ident, self.e_type, self.e_machine, self.e_version, self.e_entry,
				self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize,
				self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx
			) = header_tuple

		def __str__(self):
			return "{EOP: %#x, SectionHeaderOff: %#x, SectionHeaderSize: %#x, ProgramHeaderOff: %#x, ProgramHeaderSize: %#x, Type: %#x}" % \
						(self.e_entry, self.e_shoff, self.e_shnum * self.e_shentsize, self.e_phoff, self.e_phentsize * self.e_phnum, self.e_type)

		def pack_header(self):
			return pack(
						"16sHHIQQQIHHHHHH",	self.e_ident, self.e_type, self.e_machine, self.e_version, self.e_entry,
							self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize,
							self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx
						)
	
		def is_PIE(self):
			return self.e_type == 0x03
	
	class Elf64_Shdr:
		def __init__(self, header_tuple):
			"""
				sh_name			:		Contains the offset, in bytes, to the section name, relative to the start of the section name string table. 
				sh_type			:		Identifies the section type. Table 8 lists the processor-independent values for this field. 
				sh_flags		:		Identifies the attributes of the section. Table 9 lists the processor-independent values for these flags. 
				sh_addr			:		Contains the virtual address of the beginning of the section in memory. 
				sh_offset		:		Contains the offset, in bytes, of the beginning of the section contents in the file. 
				sh_size			:		Contains the size, in bytes, of the section.
				sh_link			:		Contains the section index of an associated section.
				sh_info			:		Contains extra information about the section.
				sh_addralign	:		Contains the required alignment of the section.
				sh_entsize		:		Contains the size, in bytes, of each entry, for sections that contain fixed-size entries.
			"""
			(
				self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset, 
				self.sh_size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize
			) = header_tuple
			self._name = None
		
		def __str__(self):
			return self._name + ":\n\t\t\t {NameOffset: " + str(hex(self.sh_name)) + ", SectionType: " + str(hex(self.sh_type)) + ", SectionOffset: " +\
						str(hex(self.sh_offset)) + ", SectionAddr: " + str(hex(self.sh_addr)) + ", SectionSize: " + str(hex(self.sh_size)) + "}"
	
		def pack_header(self):
			return pack("IIQQQQIIQQ",
						self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset, 
						self.sh_size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize
					)
	
	class Elf64_Phdr:
		def __init__(self, header_tuple):
			"""
				p_type			:		Identifies the type of segment.
				p_flags			:		Contains the segment attributes.
				p_offset		:		Contains the offset, in bytes, of the segment from the beginning of the file.
				p_vaddr			:		Contains the virtual address of the segment in memory.
				p_paddr			:		Is reserved for systems with physical addressing.
				p_filesz		:		Contains the size, in bytes, of the file image of the segment.
				p_memsz			:		Contains the size, in byres, of the memory image of the segment.
				p_align			:		Specifies the alignement constraint for the segment.
			"""
			(
				self.p_type, self.p_flags, self.p_offset, self.p_vaddr,
				self.p_paddr, self.p_filesz, self.p_memsz, self.p_allign
			) = header_tuple
		
		def __str__(self):
			return "{OffsetFile: %#x, VAddr: %#x, PAddr: %#x, SizeFile: %#x, SizeMem: %#x, Type: %#x}" % \
						(self.p_offset,self.p_vaddr,self.p_paddr,self.p_filesz,self.p_memsz,self.p_type)
	
		def pack_header(self):
			return pack("IIQQQQQQ",
						self.p_type, self.p_flags, self.p_offset, self.p_vaddr,
						self.p_paddr, self.p_filesz, self.p_memsz, self.p_allign
					)
				

	def __init__(self, elf_):
		self.header = self.Elf64_Ehdr(elf=elf_)
		self.elf = elf_
		self.eop = self.header.e_entry 		 			# Original entry point
		self.ph_table_off = self.header.e_phoff			# Program header table offset
		self.sh_table_off = self.header.e_shoff			# Section header table offset
		self.segments = self._get_segments(elf_)
		self.sections, self.str_offset = self._get_sections(elf_)
		self.h_p = None
		if self.header.e_ehsize != self.header.e_phoff:
			self.h_p = elf_[self.header.e_ehsize:self.header.e_phoff-1]
		self.p_s = None
		if self.header.e_shoff != (self.header.e_phoff + self.header.e_phnum * self.header.e_phentsize):
			self.p_s = elf_[(self.header.e_phoff + self.header.e_phnum * self.header.e_phentsize):self.header.e_shoff-1]
	
	def _get_sections(self, elf):
		## Reading the section header table
		sh_entries = self.header.e_shnum             # Number of entries in the section header table
		sh_size = self.header.e_shentsize            # Size of entries in the section header table
		sh_strings = self.header.e_shstrndx          # Strings table index
		sh_offset = None
		sections = []
		for i in xrange(sh_entries):
			off_entry = (self.sh_table_off + i*sh_size)
	#		print (unpack("IIQQQQIIQQ", elf[ off_entry : off_entry + sh_size]))
			section_header = self.Elf64_Shdr(unpack("IIQQQQIIQQ", elf[ off_entry : off_entry + sh_size]))
			sections.append(section_header)
			if section_header.sh_type == 3 and sh_offset == None:
				if sh_strings == i:
					sh_offset = section_header.sh_offset

		### Getting the text section
		text_offset = None
		text_size = None
		text_section = None
		for section in sections:
			section._name = get_c_string(elf, sh_offset + section.sh_name)

		return sections, sh_offset

	def _get_segments(self, elf):
		## Reading the program header table
		ph_entries = self.header.e_phnum
		ph_size = self.header.e_phentsize
		segments = []
	
		for i in xrange(ph_entries):
			off_entry = (self.ph_table_off + i*ph_size)
			segment_header = self.Elf64_Phdr(unpack("IIQQQQQQ", elf[ off_entry : off_entry + ph_size ]))
			print segment_header
			segments.append(segment_header)
		return segments
	
	def __str__(self):
		res = str(self.header) + "\n"
		for section in self.sections:
			res +=  str(section) + "\n"
		for segment in self.segments:
			res += str(segment) + "\n"
		return res

	def write_elf(self, filename):
		with open(filename, "wb") as f:
			f.write(self.header.pack_header())
			if self.h_p != None:
				f.write(self.h_p)
			for segment in self.segments:
				f.write(segment.pack_header())
			if self.p_s != None:
				f.write(self.p_s)
			for section in self.sections:
				f.write(section.pack_header())

	def embed(self, em_file, filename):
		new_off = len(em_file)
		self.header.e_entry += new_off
		self.header.e_phoff += new_off
		self.header.e_shoff += new_off
		for section in self.sections:
			if section.sh_offset != 0x00:
				section.sh_offset += new_off
			if section.sh_addr != 0x00:
				section.sh_addr += new_off
		for segment in self.segments:
			if segment.p_offset != 0x00:
				segment.p_offset += new_off
		if self.h_p != None:
			self.h_p = em_file + self.h_p
		else:
			self.h_p = em_file
		self.write_elf(filename)


