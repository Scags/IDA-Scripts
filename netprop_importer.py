import idautils
import idaapi
import idc
from math import ceil

import sys
import xml.etree.ElementTree as et

def calcszdata(sz):
	absmax = ceil(sz/8.0)
	if absmax == 1:
		flags = idc.FF_BYTE
		numbytes = 1
	elif absmax == 2:
		flags = idc.FF_WORD
		numbytes = 2
	else:
		flags = idc.FF_DWRD
		numbytes = 4

	return flags, numbytes

# Doesn't exactly work with recursive sendtables
# This nutty recursion really fucking hurts my head
def get_sendtable_size(sendtable):
	size = 0
	highestoffset = 0
	for c in sendtable:
		add = 0
		t = c.find("type")
		if t == None:
			continue

		offset = c.find("offset")
		offset = int(offset.text) if offset != None else None

		if highestoffset < offset:
			highestoffset = offset

		if t.text == "datatable":
			sendtable2 = c.find("sendtable")
			if sendtable2 != None:
				mycls = sendtable2.attrib.get("name", None)
				if mycls != None:
				 	if not mycls.startswith("DT_"):		# An array with a baseclass datatable? Oh well
						add = get_sendtable_size(sendtable2)
		else:
			sz = c.find("bits")
			sz = int(sz.text) if sz != None else None
			if sz == None:
				return

			_, numbytes = calcszdata(sz)
			add = numbytes

		size = add + highestoffset

	# Round up to the nearest 4 byte multiple
	size = int(ceil(size / 4.0) * 4)
	return size

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
				if offset == None or offset is 0:
					return

				# Have to be a little special with datatables
				# Don't know how to import structs as struct members yet :(
				if t.text == "datatable":
					ida_struct.add_struc_member(struc, classname, offset, idc.FF_DWRD, None, 4)
					sendtable = c.find("sendtable")
					if sendtable != None:
						mycls = sendtable.attrib.get("name", None)
						if mycls != None:
						 	if mycls.startswith("DT_"):
								mycls = mycls.replace("DT_", "C", 1)
								strucid = ida_struct.get_struc_id(mycls)
								if strucid != idc.BADADDR:
									ida_struct.del_struc(ida_struct.get_struc(strucid))
								parse(sendtable, ida_struct.get_struc(ida_struct.add_struc(idc.BADADDR, mycls)))
							else:	# Iterate the array and update the struct member size, hackily
								sizemult = get_sendtable_size(sendtable)
								if sizemult > 4:
									ida_struct.set_member_type(struc, offset, idc.FF_DWRD, None, sizemult)
					return

				sz = c.find("bits")
				sz = int(sz.text) if sz != None else None
				if sz == None:
					return

				flags, numbytes = calcszdata(sz)

#				if t.text == "float":
#					flags |= idc.FF_FLOAT

#				print(idc.FF_BYTE, idc.FF_DWRD)
#				print(flags, numbytes)

				if t.text == "vector":
					ida_struct.add_struc_member(struc, classname, offset, idc.FF_DWRD, None, 12)
				else:
					returnval = ida_struct.add_struc_member(struc, classname, offset, flags, None, numbytes)
					if returnval:
						print("Could not add struct member {}::{}! Error {}".format(ida_struct.get_struc_name(struc.id), classname, returnval))

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
	struc = ida_struct.get_struc(ida_struct.add_struc(idc.BADADDR, classname))

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
		struc = ida_struct.get_struc(ida_struct.add_struc(idc.BADADDR, "Vector"))
		ida_struct.add_struc_member(struc, "x", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "y", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "z", idc.BADADDR, idc.FF_DWRD, None, 4)

	strucid = ida_struct.get_struc_id("QAngle")
	if strucid == idc.BADADDR:
		struc = ida_struct.get_struc(ida_struct.add_struc(idc.BADADDR, "QAngle"))
		ida_struct.add_struc_member(struc, "x", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "y", idc.BADADDR, idc.FF_DWRD, None, 4)
		ida_struct.add_struc_member(struc, "z", idc.BADADDR, idc.FF_DWRD, None, 4)

def main():
	data = None
	with open(ida_kernwin.ask_file(0, "*.xml", "Select a file to import")) as f:
		data = f.readlines()

	if data is None:
		return

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