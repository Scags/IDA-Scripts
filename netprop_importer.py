import idautils
import idaapi
import idc
from math import ceil

import sys
import xml.etree.ElementTree as et

VECTOR = None

def parse(c, struc):
	if c.tag == "sendtable":
	 	if c.attrib.get("name", None) and c.attrib.get("name", None).startswith("DT_"):
	 		for i in c:
				parse(i, struc)
	elif c.tag == "property":
		classname = c.attrib.get("name", None)
		if classname != None:
			if classname == "baseclass":
				for p in c:
					parse(p, struc)
			else:
				t = c.find("type")
				if t == None:
					return

				offset = c.find("offset")
				offset = int(offset.text) if offset != None else None
				if not offset or offset is 0:
					return

				# Have to be a little special with datatables
				# Don't know how to import structs as struct members yet :(
				if t.text == "datatable":
					ida_struct.add_struc_member(struc, classname, offset, idc.FF_DWRD, None, 4)
					sendtable = c.find("sendtable")
					if sendtable != None:
						mycls = sendtable.attrib.get("name", None)
						if mycls != None and mycls.startswith("DT_"):
							mycls = mycls.replace("DT_", "C", 1)
							strucid = ida_struct.get_struc_id(mycls)
							if strucid != idc.BADADDR:
								ida_struct.del_struc(ida_struct.get_struc(strucid))
							parse(sendtable, ida_struct.get_struc(ida_struct.add_struc(ida_struct.get_last_struc_idx()+1, mycls)))
					return

				sz = c.find("bits")
				sz = int(sz.text) if sz != None else None
				if sz == None:
					return

				absmax = ceil(sz/8.0)
				if absmax == 1:
					size = idc.FF_BYTE
					numbytes = 1
				elif absmax == 2:
					size = idc.FF_WORD
					numbytes = 2
				else:
					size = idc.FF_DWRD
					numbytes = 4

#				print(idc.FF_BYTE, idc.FF_DWRD)
#				print(size, numbytes)

				if t.text == "vector":
					global VECTOR
					# Why doesn't this assign as a Vector?
					ida_struct.add_struc_member(struc, classname, offset, idc.FF_DWRD, VECTOR, 12)
				else:
					returnval = ida_struct.add_struc_member(struc, classname, offset, size, None, numbytes)
					if returnval:
						print("Could not add struct member {}.{}! Error {}".format(ida_struct.get_struc_name(struc.id), classname, returnval))

def parse_class(c):
	if c is None:
		return

	if c.tag != "serverclass":
		return

	classname = c.attrib["name"]
	ida_kernwin.replace_wait_box("Importing {}".format(classname))
	struc = None
	strucid = ida_struct.get_struc_id(classname)
	if strucid != idc.BADADDR:
		ida_struct.del_struc(ida_struct.get_struc(strucid))
	struc = ida_struct.get_struc(ida_struct.add_struc(ida_struct.get_last_struc_idx()+1, classname))

	if len(c):
		parse(c[0], struc)

# Fix SM's bad xml structure
def fix_xml(data):
	for i in xrange(len(data)):
		data[i] = data[i].replace('""', '"')

	data[3] = "<root name=\"root\">\n"
	data.append("</root>\n")
	return data

# Make Vector and QAngle structs to keep things sane
def make_basic_structs():
	strucid = ida_struct.get_struc_id("Vector")
	if strucid == idc.BADADDR:
		struc = ida_struct.get_struc(ida_struct.add_struc(ida_struct.get_last_struc_idx()+1, "Vector"))
		ida_struct.add_struc_member(struc, "x", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "y", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "z", idc.BADADDR, idc.FF_DWRD, None, 4)

	global VECTOR
	VECTOR = idaapi.opinfo_t()
	if ida_bytes.get_opinfo(VECTOR, 0, ida_bytes.get_flags(strucid), ida_struct.get_struc_first_offset(ida_struct.get_struc(strucid))):
		print(VECTOR)	# 0_o

	strucid = ida_struct.get_struc_id("QAngle")
	if strucid == idc.BADADDR:
		struc = ida_struct.get_struc(ida_struct.add_struc(ida_struct.get_last_struc_idx()+1, "QAngle"))
		ida_struct.add_struc_member(struc, "x", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "y", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "z", idc.BADADDR, idc.FF_DWRD, None, 4)


def main():
	data = None
	with open(ida_kernwin.ask_file(0, "*.xml", "Select a file to import")) as f:
		data = f.readlines()
	
	ida_kernwin.show_wait_box("Importing file")
	fix_xml(data)
	make_basic_structs()

	tree = et.fromstringlist(data)
	if (tree is None):
		ida_kernwin.hide_wait_box()
		ida_kernwin.warning("Something bad happened :(")
		return

	for i in tree:
		parse_class(i)

	ida_kernwin.hide_wait_box()


if __name__ == "__main__":
	main()