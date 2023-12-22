import idautils
import idaapi
import idc
import ctypes
import time

from math import ceil

import xml.etree.ElementTree as et

from dataclasses import dataclass
from enum import Enum

if idaapi.inf_is_64bit():
	ea_t = ctypes.c_uint64
	FF_PTR = idc.FF_QWORD
else:
	ea_t = ctypes.c_uint32
	FF_PTR = idc.FF_DWORD

class DataCache(object):
	tablecache = {}

class SendPropType(Enum):
	DPT_Int = 0
	DPT_Float = 1
	DPT_Vector = 2
	DPT_VectorXY = 3
	DPT_String = 4
	DPT_Array = 5
	DPT_DataTable = 6
	DPT_Int64 = 7

class SendFlags(Enum):
	UNSIGNED = 1 << 0
	COORD = 1 << 1
	NOSCALE = 1 << 2
	ROUNDDOWN = 1 << 3
	ROUNDUP = 1 << 4
	NORMAL = 1 << 5
	EXCLUDE = 1 << 6
	XYZE = 1 << 7
	INSIDEARRAY = 1 << 8
	PROXY_ALWAYS_YES = 1 << 9
	CHANGES_OFTEN = 1 << 10
	IS_A_VECTOR_ELEM = 1 << 11
	COLLAPSIBLE = 1 << 12
	COORD_MP = 1 << 13
	COORD_MP_LOWPRECISION = 1 << 14
	COORD_MP_INTEGRAL = 1 << 15
	VARINT = NORMAL
	ENCODED_AGAINST_TICKCOUNT = 1 << 16

@dataclass(frozen=True)
class SendProp:
	name: str
	type: int	#SendPropType
	offset: int
	bits: int
	flags: int
	table: 'SendTable' = None

	def __repr__(self):
		# Use id() with table or else infinite recursion
		return f"SendProp(name={self.name}, type={self.type}, offset={self.offset}, bits={self.bits}, flags={self.flags}, table={id(self.table):#x})"
	
	def add_to_struc(self, struc, offset):
		# So, unfortunately, it doesn't seem to be possible to implement baseclasses
		# while also keeping vtables intact. This might actually be possible as it can be done
		# with IDA's header parser, but this might not be exposed to the API.
		# Implementing baseclasses with seamless vtable integration is a TODO
		# The framework is more or less here, so if I manage to figure that out it won't
		# be that difficult to implement
		# Might have to do with optinfo_t pointing to the proper vtable? Dunno
		# if self.table is not None:
		# 	baseclass = DataCache.struccache.get(self.table.classname, None)
		# 	if baseclass is None:
		# 		self.table.create_struc()

		# 	baseclass = DataCache.struccache[self.table.classname]

		if self.table is not None:
			# Array
			# We *could* parse these and implement them as embedded classes/arrays
			# but there's no guarantee that we would get a proper size, which could
			# cause some really poor results
			# There's a good chance that more array data is actually in the inner table's m_pExtraData
			# Mayhaps a SourceMod PR for another time
			if not self.table.name.startswith("_ST_"):
				# Bad hack but catches arrays
				if self.table.name == self.name:
					if self.offset != 0:
						self.table.add_array_to_struc(struc, offset + self.offset)
					return
				else:
					self.table.add_to_struc(struc, offset + self.offset)

		# Offset is 0 so we die
		if self.offset == 0:
			return

		curroffset = self.offset + offset

		currmem = idaapi.get_member(struc, curroffset)
		if currmem is not None:
#			print(f"Member {self.name} already exists in {idaapi.get_struc_name(struc.id)}")
			return

		idaflags, sz = self.calc_sz()
		tinfo = self.get_tinfo()
		targetname = idaapi.validate_name(self.name, idaapi.VNT_IDENT)

		serr = idaapi.add_struc_member(struc, targetname, curroffset, idaflags, None, sz)
		if serr != idaapi.STRUC_ERROR_MEMBER_OK:
			# I really don't wanna deal with these silly subclasses
			if serr < idaapi.STRUC_ERROR_MEMBER_OFFSET:
				print(f"Could not add struct member {idaapi.get_struc_name(struc.id)}.{targetname} at {curroffset} ({curroffset:#x})! Error {serr}")
			return

		currmem = idaapi.get_member(struc, curroffset)
		if tinfo is not None:
			idaapi.set_member_tinfo(struc, currmem, 0, tinfo, 0)
		elif self.flags and self.flags & SendFlags.UNSIGNED.value:
			currinfo = idaapi.tinfo_t()
			if idaapi.get_member_tinfo(currinfo, currmem):
				currinfo.change_sign(idaapi.type_unsigned)
				idaapi.set_member_tinfo(struc, currmem, 0, currinfo, 0)

	def calc_sz(self):
		if self.type == SendPropType.DPT_Float.value:
			return idc.FF_FLOAT, 4
		elif self.type == SendPropType.DPT_Int64.value:
			return idc.FF_QWORD, 8
		elif self.type == SendPropType.DPT_String.value:
			return FF_PTR, ctypes.sizeof(ea_t)
		elif self.type == SendPropType.DPT_Vector.value:
			# Returning FF_STRUCT doesn't work because the proper opinfo_t needs to be set
			# but this can be cheesed by just setting it to FF_DWORD and setting the tinfo after
			return idc.FF_DWORD, 12 #idc.FF_STRUCT

		absmax = ceil(self.bits/8.0)
		if absmax == 1:
			flags = idc.FF_BYTE
			numbytes = 1
		elif absmax == 2:
			flags = idc.FF_WORD
			numbytes = 2
		else:
			flags = idc.FF_DWORD
			numbytes = 4

		return flags, numbytes

	def get_tinfo(self):
		return {
			SendPropType.DPT_Vector.value: VECTOR,
#			SendPropType.DPT_Int.value: idaapi.tinfo_t(idaapi.BT_INT),
			SendPropType.DPT_Float.value: idaapi.tinfo_t(idaapi.BT_FLOAT),
#			SendPropType.DPT_String.value: idaapi.tinfo_t(idaapi.BT_PTR),
			SendPropType.DPT_Int64.value: idaapi.tinfo_t(idaapi.BT_INT64),
		}.get(self.type, None)

@dataclass
class SendTable:
	name: str
	props: list[SendProp]
	# For mapping to a "C"-class
	# I'm gonna assume that there'll be some game that won't suffice with a "replace DT_ with C" method,
	# so we have SendTable objects point to their actual class name
	classname: str

	@staticmethod
	def create(elem:et.Element, classname=None):
		name = elem.attrib["name"]

		# Check if we've already cached this table, update classname if so
		# because if this is true, then its classname is surely missing
		if name in DataCache.tablecache:
			if classname is not None:
				DataCache.tablecache[name].classname = classname
			return DataCache.tablecache[name]

		props = []
		for p in elem:
			pname = p.attrib["name"]

			# Collect and format the fields
			stype = p.find("type").text if p.find("type") != None else None
			ptype = str_to_dt_type(stype)
			sflags = p.find("flags").text if p.find("flags") != None else None
			flags = str_to_sendflags(sflags)
			offset = int(p.find("offset").text) if p.find("offset") != None else None
			bits = int(p.find("bits").text) if p.find("bits") != None else None
			ptable = SendTable.create(p.find("sendtable")) if p.find("sendtable") != None else None

			# Append a new prop
			props.append(SendProp(pname, ptype, offset, bits, flags, ptable))

		# Cache and return
		DataCache.tablecache[name] = SendTable(name, props, classname)
		return DataCache.tablecache[name]
	
	def create_struc(self):
		struc = add_struc_ex(self.classname)

		self.add_to_struc(struc, 0)

		#DataCache.struccache[self.classname] = struc
	
	def add_to_struc(self, struc, offset):
		for prop in self.props:
			prop.add_to_struc(struc, offset)

	def add_array_to_struc(self, struc, offset):
		if offset == 0:
			return

		idaflags, sz = self.props[0].calc_sz()
		if len(self.props) > 1:
			sz = (self.props[1].offset - self.props[0].offset)
			idaflags = sz_to_idaflags(sz)

		sz *= len(self.props)

		tinfo = self.props[0].get_tinfo()
		targetname = idaapi.validate_name(self.name, idaapi.VNT_IDENT)

		serr = idaapi.add_struc_member(struc, targetname, offset, idaflags, None, sz)
		if serr != idaapi.STRUC_ERROR_MEMBER_OK:
			# I really don't wanna deal with these silly subclasses
			if serr < idaapi.STRUC_ERROR_MEMBER_OFFSET:
				print(f"Could not add struct member {idaapi.get_struc_name(struc.id)}.{targetname} at {offset} ({offset:#x})! Error {serr}")
			return

		currmem = idaapi.get_member(struc, offset)
		if tinfo is not None:
			idaapi.set_member_tinfo(struc, currmem, 0, tinfo, 0)
		elif self.props[0].flags and self.props[0].flags & SendFlags.UNSIGNED.value:
			currinfo = idaapi.tinfo_t()
			if idaapi.get_member_tinfo(currinfo, currmem):
				currinfo.change_sign(idaapi.type_unsigned)
				idaapi.set_member_tinfo(struc, currmem, 0, currinfo, 0)

@dataclass(frozen=True)
class ServerClass:
	name: str
	sendtable: SendTable

	@staticmethod
	def create(elem: et.Element, classname):
		sendtable = elem.find("sendtable")
		return ServerClass(classname, SendTable.create(sendtable, classname))
	
	def create_struc(self):
		self.sendtable.create_struc()


# Idiot proof IDA wait box
class WaitBox:
	buffertime = 0.0
	shown = False
	msg = ""

	@staticmethod
	def _show(msg):
		WaitBox.msg = msg
		if WaitBox.shown:
			idaapi.replace_wait_box(msg)
		else:
			idaapi.show_wait_box(msg)
			WaitBox.shown = True

	@staticmethod
	def show(msg, buffertime=0.1):
		if msg == WaitBox.msg:
			return

		if buffertime > 0.0:
			if time.time() - WaitBox.buffertime < buffertime:
				return
			WaitBox.buffertime = time.time()
		WaitBox._show(msg)

	@staticmethod
	def hide():
		if WaitBox.shown:
			idaapi.hide_wait_box()
			WaitBox.shown = False

VECTOR = None

def str_to_dt_type(t):
	return {
		"int": SendPropType.DPT_Int.value,
		"float": SendPropType.DPT_Float.value,
		"vector": SendPropType.DPT_Vector.value,
		"string": SendPropType.DPT_String.value,
		"array": SendPropType.DPT_Array.value,
		"datatable": SendPropType.DPT_DataTable.value,
		"int64": SendPropType.DPT_Int64.value
	}.get(t, None)

def str_to_sendflags(s):
	if not s:
		return s

	splode = s.split("|")
	d = {
		"Unsigned": SendFlags.UNSIGNED.value,
		"Coord": SendFlags.COORD.value,
		"NoScale": SendFlags.NOSCALE.value,
		"RoundDown": SendFlags.ROUNDDOWN.value,
		"RoundUp": SendFlags.ROUNDUP.value,
		"VarInt": SendFlags.NORMAL.value,
		"Normal": SendFlags.NORMAL.value,
		"Exclude": SendFlags.EXCLUDE.value,
		"XYZE": SendFlags.XYZE.value,
		"InsideArray": SendFlags.INSIDEARRAY.value,
		"AlwaysProxy": SendFlags.PROXY_ALWAYS_YES.value,
		"ChangesOften": SendFlags.CHANGES_OFTEN.value,
		"VectorElem": SendFlags.IS_A_VECTOR_ELEM.value,
		"Collapsible": SendFlags.COLLAPSIBLE.value,
		"CoordMP": SendFlags.COORD_MP.value,
		"CoordMPLowPrec": SendFlags.COORD_MP_LOWPRECISION.value,
		"CoordMpIntegral": SendFlags.COORD_MP_INTEGRAL.value,
	}
	flags = 0
	for fl in splode:
		flags |= d.get(fl, 0)

	return flags

def sz_to_idaflags(sz):
	return {
		1: idc.FF_BYTE,
		2: idc.FF_WORD,
		4: idc.FF_DWORD,
		8: idc.FF_QWORD
	}.get(sz, 1)
	

def add_struc_ex(name):
	strucid = idaapi.get_struc_id(name)
	if strucid == idc.BADADDR:
		strucid = idaapi.add_struc(idc.BADADDR, name)

	return idaapi.get_struc(strucid)

def calcszdata(sz):
	absmax = ceil(sz/8.0)
	if absmax == 1:
		flags = idc.FF_BYTE
		numbytes = 1
	elif absmax == 2:
		flags = idc.FF_WORD
		numbytes = 2
	else:
		flags = idc.FF_DWORD
		numbytes = 4

	return flags, numbytes

# Fix SM's bad xml structure
def fix_xml(data):
	for i in range(len(data)):
		data[i] = data[i].replace('""', '"')

	data[3] = "<root>\n"
	data.append("</root>\n")
	return data

# Make Vector and QAngle structs to keep things sane
def make_basic_structs():
	strucid = idaapi.get_struc_id("Vector")
	if strucid == idc.BADADDR:
		struc = idaapi.get_struc(idaapi.add_struc(idc.BADADDR, "Vector"))
		idaapi.add_struc_member(struc, "x", idc.BADADDR, idc.FF_FLOAT|idc.FF_DATA, None, 4)
		idaapi.add_struc_member(struc, "y", idc.BADADDR, idc.FF_FLOAT|idc.FF_DATA, None, 4)
		idaapi.add_struc_member(struc, "z", idc.BADADDR, idc.FF_FLOAT|idc.FF_DATA, None, 4)
		strucid = idaapi.get_struc_id("Vector")

	global VECTOR
	VECTOR = idaapi.tinfo_t()
	if idaapi.guess_tinfo(VECTOR, strucid) == idaapi.GUESS_FUNC_FAILED:
		VECTOR = None

	strucid = idaapi.get_struc_id("QAngle")
	if strucid == idc.BADADDR:
		struc = idaapi.get_struc(idaapi.add_struc(idc.BADADDR, "QAngle"))
		idaapi.add_struc_member(struc, "x", idc.BADADDR, idc.FF_FLOAT|idc.FF_DATA, None, 4)
		idaapi.add_struc_member(struc, "y", idc.BADADDR, idc.FF_FLOAT|idc.FF_DATA, None, 4)
		idaapi.add_struc_member(struc, "z", idc.BADADDR, idc.FF_FLOAT|idc.FF_DATA, None, 4)

def main():
	data = None
	try:
		fopen = idaapi.ask_file(0, "*.xml", "Select a file to import")
		if fopen is None:
			return

		idaapi.set_ida_state(idaapi.st_Work)
		WaitBox.show("Parsing XML")
		with open(fopen) as f:
			data = f.readlines()

		if data is None:
			idaapi.set_ida_state(idaapi.st_Ready)
			return

		make_basic_structs()

		try:
			# SM 1.10 <= has bad XML, assume its correct first then try to fix it
			tree = et.fromstringlist(data)
		except:
			fix_xml(data)
			tree = et.fromstringlist(data)

		if tree is None:
			idaapi.warning("Something bad happened :(")
			idaapi.set_ida_state(idaapi.st_Ready)
			return

		WaitBox.show("Creating ServerClasses")
		classes = {}
		for cls in tree:
			classname = cls.attrib["name"]
			classes[classname] = ServerClass.create(cls, classname)

		idaapi.begin_type_updating(idaapi.UTP_STRUCT)

		WaitBox.show("Adding struct members")
		for classname, serverclass in classes.items():
			serverclass.create_struc()

		print("Done!")
	except:
		import traceback
		traceback.print_exc()
		print("Please file a bug report with supporting information at https://github.com/Scags/IDA-Scripts/issues")
		idaapi.beep()

	WaitBox.hide()
	idaapi.end_type_updating(idaapi.UTP_STRUCT)
	idaapi.set_ida_state(idaapi.st_Ready)

main()