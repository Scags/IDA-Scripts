import idautils
import idaapi
import idc
from math import ceil

import xml.etree.ElementTree as et

IMPORT_VTABLE = 0
VECTOR = None

def add_struc_ex(name):
	strucid = ida_struct.get_struc_id(name)
	if strucid == idc.BADADDR:
		strucid = ida_struct.add_struc(idc.BADADDR, name)

	return strucid

def add_struc_ex2(name):
	strucid = ida_struct.get_struc_id(name)
	if strucid != idc.BADADDR:
		ida_struct.del_struc(ida_struct.get_struc(strucid))

	return ida_struct.add_struc(idc.BADADDR, name)

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
	highestflag = idc.FF_BYTE
	for c in sendtable:
		add = 0
		t = c.find("type")
		if t == None:
			continue

		offset = c.find("offset")
		offset = int(offset.text) if offset != None else None

		highestoffset = max(offset, highestoffset)

		if t.text == "datatable":
			sendtable2 = c.find("sendtable")
			if sendtable2 != None:
				mycls = sendtable2.attrib.get("name", None)
				if mycls != None:
				 	if not mycls.startswith("DT_"):		# An array with a baseclass datatable? Oh well
						flag, add = get_sendtable_size(sendtable2)
						highestflag = max(flag, highestflag)
		else:
			sz = c.find("bits")
			sz = int(sz.text) if sz != None else None
			if sz == None:
				return

			flag, numbytes = calcszdata(sz)
			if t.text == "float":
				flags = idc.FF_FLOAT
				numbytes = 4
			highestflag = max(flag, highestflag)
			add = numbytes

		size = add + highestoffset

	# Round up to the nearest 4 byte multiple
#	size = int(ceil(size / 4.0) * 4)
	# Actually don't, some bools can get squeezed in there (e.g. CParticleSystem.m_bWeatherEffect)
	return highestflag, size

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
				if t.text == "datatable":
					ida_struct.add_struc_member(struc, classname, offset, idc.FF_DWRD, None, 4)
					sendtable = c.find("sendtable")
					if sendtable != None:
						mycls = sendtable.attrib.get("name", None)
						if mycls != None:
						 	if mycls.startswith("DT_"):
								mycls = mycls.replace("DT_", "C", 1)
								strucid = ida_struct.get_struc_id(mycls)
								if strucid == idc.BADADDR:	# If this struct didn't exist, parse it
									strucid = ida_struct.add_struc(idc.BADADDR, mycls)
									parse(sendtable, ida_struct.get_struc(strucid))
								ti = idaapi.tinfo_t()	# Assign the sendtable type to the struct
								idaapi.parse_decl2(None, mycls + ";", ti, 0)
								if str(ti) != "CAttributeList":		# HACK; this one doesn't work and idk what else to try
									ida_struct.set_member_tinfo(struc, ida_struct.get_member(struc, offset), 0, ti, 0)
							else:	# Iterate the array and update the struct member size, hackily
								flag, sizemult = get_sendtable_size(sendtable)
								if sizemult > 4:
									ida_struct.set_member_type(struc, offset, flag, None, sizemult)
					return

				sz = c.find("bits")
				sz = int(sz.text) if sz != None else None
				if sz == None:
					return

				flags, numbytes = calcszdata(sz)

				if t.text == "float":
					flags = idc.FF_FLOAT
					numbytes = 4

#				print(idc.FF_BYTE, idc.FF_DWRD)
#				print(flags, numbytes)

				if t.text == "vector":
					ida_struct.add_struc_member(struc, classname, offset, idc.FF_DWRD, None, 12)
					global VECTOR
					ida_struct.set_member_tinfo(struc, ida_struct.get_member(struc, offset), 0, VECTOR, 0)
				else:
					returnval = ida_struct.add_struc_member(struc, classname, offset, flags, None, numbytes)
					if returnval:
						print("Could not add struct member {}.{}! Error {}".format(ida_struct.get_struc_name(struc.id), classname, returnval))

def get_vtable(name):
	# So, to assure that we're in a vtable, we need to find the thisoffset
	# So we remangle this fucker
	mangledname = "_ZTV{}{}".format(len(name), name)
	# Then get the address where this mangled thisoffs is stored
	return idc.get_name_ea_simple(mangledname)

def import_vtable(classname, struc):
	ea = get_vtable(classname)
	if ea == idc.BADADDR:
		return

	# Mildly adapted from Asherkin's vtable dumper
	ea = ea + 8		# Skip typeinfo and thisoffs

	funcs = []
	while ea != idc.BADADDR:
		offs = idc.get_wide_dword(ea)
		if not ida_bytes.is_code(ida_bytes.get_full_flags(offs)):
			break
		name = idc.get_name(offs, ida_name.GN_VISIBLE)
		funcs.append(name)

		ea = ida_bytes.next_not_tail(ea)

#	print(funcs)

	if not len(funcs):
		return

	strucid = add_struc_ex2(classname + "_vftable")
	vstruc = ida_struct.get_struc(strucid)
	for i in funcs:
		# Gotta do a fancy demangle, it can't have special chars
		# and there can't be multiples of the same name, so let's just jazz around all of that
		demangled = idc.demangle_name(i, idc.get_inf_attr(idc.INF_SHORT_DN))
		if demangled == None:
			demangled = i
		else:
			demangled = demangled[demangled.find("::")+2:demangled.find("(")]
			demangled = demangled.replace("~", "_").replace("<", "_").replace(">", "_")
		while 1:
			error = ida_struct.add_struc_member(vstruc, demangled, idc.BADADDR, idc.FF_DWRD, None, 4)

			if error == 0:
				break

			demangled = demangled + "_"		# This is dumb but lol

	# Now assign the vtable to the actual struct
	ti = idaapi.tinfo_t()
	idaapi.parse_decl2(None, classname + "_vftable;", ti, 0)
	ti.create_ptr(ti)
	ida_struct.set_member_tinfo(struc, ida_struct.get_member(struc, 0), 0, ti, 0)

def parse_class(c):
	if c is None:
		return

	if c.tag != "serverclass":
		return

	classname = c.attrib["name"]

	ida_kernwin.replace_wait_box("Importing {}".format(classname))
	strucid = add_struc_ex(classname)
	struc = ida_struct.get_struc(strucid)

	# Add the vtable here, anywhere else and it might be slotted into a class w/o vfuncs
	m = ida_struct.get_member(struc, 0)
	if m == None:
		ida_struct.add_struc_member(struc, "vftable", 0, idc.FF_DWRD, None, 4)

	global IMPORT_VTABLE
	if IMPORT_VTABLE:
		import_vtable(classname, struc)

	if len(c):
		parse(c[0], struc)

# Fix SM's bad xml structure
def fix_xml(data):
	for i in range(len(data)):
		data[i] = data[i].replace('""', '"')

	data[3] = "<root name=\"root\">\n"
	data.append("</root>\n")
	return data

# Make Vector and QAngle structs to keep things sane
def make_basic_structs():
	strucid = ida_struct.get_struc_id("Vector")
	if strucid == idc.BADADDR:
		struc = ida_struct.get_struc(ida_struct.add_struc(idc.BADADDR, "Vector"))
		ida_struct.add_struc_member(struc, "x", idc.BADADDR, idc.FF_FLOAT, None, 4)
		ida_struct.add_struc_member(struc, "y", idc.BADADDR, idc.FF_FLOAT, None, 4)
		ida_struct.add_struc_member(struc, "z", idc.BADADDR, idc.FF_FLOAT, None, 4)

	global VECTOR
	VECTOR = idaapi.tinfo_t()
	idaapi.parse_decl2(None, "Vector;", VECTOR, 0)

	strucid = ida_struct.get_struc_id("QAngle")
	if strucid == idc.BADADDR:
		struc = ida_struct.get_struc(ida_struct.add_struc(idc.BADADDR, "QAngle"))
		ida_struct.add_struc_member(struc, "x", idc.BADADDR, idc.FF_FLOAT, None, 4)
		ida_struct.add_struc_member(struc, "y", idc.BADADDR, idc.FF_FLOAT, None, 4)
		ida_struct.add_struc_member(struc, "z", idc.BADADDR, idc.FF_FLOAT, None, 4)

def main():
	ida_auto.set_ida_state(ida_auto.st_Work)
	data = None
	with open(ida_kernwin.ask_file(0, "*.xml", "Select a file to import")) as f:
		data = f.readlines()

	if data is None:
		ida_auto.set_ida_state(ida_auto.st_Ready)
		return

	ida_kernwin.show_wait_box("Importing file")
	fix_xml(data)
	make_basic_structs()

	tree = et.fromstringlist(data)
	if (tree is None):
		ida_kernwin.hide_wait_box()
		ida_kernwin.warning("Something bad happened :(")
		ida_auto.set_ida_state(ida_auto.st_Ready)
		return

	global IMPORT_VTABLE
	IMPORT_VTABLE = ida_kernwin.ask_yn(1, "Import virtual tables for classes? (Longer)")

	for i in tree:
		parse_class(i)
	ida_kernwin.hide_wait_box()
	ida_auto.set_ida_state(ida_auto.st_Ready)

if __name__ == "__main__":
	main()