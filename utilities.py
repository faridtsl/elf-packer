
def get_c_string(data, off):
	i = 0
	res = []
	while data[off+i] != '\x00':
		res.append(data[off+i])
		i += 1
	return ''.join(res)

def write_c_string(mem, string):
	for c in string:
		mem.append(ord(c))
	mem.append('\x00')
	return mem

def get_c_stringA(data, off):
	i = 0
	res = []
	while data[off+i] != 0x00:
		res.append(chr(data[off+i]))
		i += 1
	return ''.join(res)

