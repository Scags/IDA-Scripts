import idc
import idautils
import idaapi

from time import time
from math import floor

OS_Linux = 0
OS_Win = 1

OS = None

class OSData(object):
	def __init__(self, os):
		self.os = os
		if os == OS_Linux:
			self.segm = ida_segment.get_segm_by_name(".rodata")
		else:
			self.segm = ida_segment.get_segm_by_name(".rdata")

	def parse_vtable(self, ea, typename):
		if self.os == OS_Linux:
			ea += 8
		funcs = []

		while ea != idc.BADADDR:
			eatemp = ea
			offs = idc.get_wide_dword(ea)
	#		if ida_bytes.is_unknown(ida_bytes.get_full_flags(ea)):
	#			break

			size = idc.get_item_size(ea)	# This is bad abd abadbadbadbabdbabdad but there's no other choice here
			if size != 4:
				# This looks like it might be a bug with IDA
				# Random points of a vtable are getting turned into unknown data
				if size != 1:
					break

				s = "".join(["%02x" % idc.get_wide_byte(ea + i) for i in range(3, -1, -1)])
				if not s.lower().startswith("ffff"):
					ea = ida_bytes.next_not_tail(ea)
					continue

				offs = int(s, 16)
				ea += 3

			name = idc.get_name(offs, ida_name.GN_VISIBLE)
			if name:
				if self.os == OS_Linux:
					if not(name.startswith("_Z") or name.startswith("__cxa")) or name.startswith("_ZTV"):
						break 	# If we've exceeded past this vtable
				elif name.startswith("??"):
					break
			else:
				if self.os == OS_Win:
					break

				# dd -offsettothis
				# This is even worseworsoewewrosorooese
				s = "%02x" % offs
				if not s.lower().startswith("ffff"):
					ea = ida_bytes.next_not_tail(ea)
					continue

				break
			funcs.append(name)

			ea = ida_bytes.next_not_tail(ea)

		if len(funcs):
			import_vtable(typename, funcs)
		return eatemp

def add_struc_ex(name):
	strucid = ida_struct.get_struc_id(name)
	if strucid == idc.BADADDR:
		strucid = ida_struct.add_struc(idc.BADADDR, name)

	return strucid

def import_vtable(typename, funcs):
	typestrucid = add_struc_ex(typename)
	typestruc = ida_struct.get_struc(typestrucid)
	vstrucid = add_struc_ex(typename + "_vtbl")
	vstruc = ida_struct.get_struc(vstrucid)

	loffs = ida_struct.get_struc_last_offset(vstruc)
	if loffs != idc.BADADDR:
		ida_struct.del_struc_members(vstruc, 0, loffs + 4)

	for i in funcs:
		demangled = idc.demangle_name(i, idc.get_inf_attr(idc.INF_SHORT_DN))
		if demangled == None:
			demangled = i
		else:
			demangled = demangled[demangled.find("::")+2:demangled.find("(")]
			# As per https://stackoverflow.com/questions/3411771/best-way-to-replace-multiple-characters-in-a-string
			# this isn't as slow as you'd think
			demangled = demangled\
				.replace("~", "_")\
				.replace("<", "_")\
				.replace(">", "_")\
				.replace(",", "_")\
				.replace("*", "_")\
				.replace(" ", "_")\
				.replace("operator==", "__eq__")\
				.replace("operator+", "__add__")\
				.replace("operator-", "__sub__")\
				.replace("operator*", "__mul__")\
				.replace("operator/", "__div__")\
				.replace("operator%", "__mod__")\
				.replace("operator<<", "__lshift__")\
				.replace("operator>>", "__rshift__")\
				.replace("operator&", "__and__")\
				.replace("operator|", "__or__")\
				.replace("operator^", "__xor__")\
				.replace("operator~", "__invert__")
		while 1:
			error = ida_struct.add_struc_member(vstruc, demangled, idc.BADADDR, idc.FF_DWORD, None, 4)

			if error == 0:
				break

			demangled += "_{}".format(hex(ida_struct.get_struc_last_offset(vstruc) + 4)[2:])

	try:
		ti = idaapi.tinfo_t()
		idaapi.parse_decl(ti, None, typename + "_vtbl;", 0)
		ti.create_ptr(ti)
		ida_struct.add_struc_member(typestruc, "__vftable", 0, idc.FF_DWORD, None, 4)
		ida_struct.set_member_tinfo(typestruc, ida_struct.get_member(typestruc, 0), 0, ti, 0)
	except:
		print("Prevented a terrible, horrible, no good, very bad crash with {}!".format(typename))

def is_vtable(ea):
	currname = idc.get_name(ea)
	if not currname:
		return ""

	currname = idc.demangle_name(currname, idc.get_inf_attr(idc.INF_SHORT_DN))
	if not currname:
		return ""

	# These break everything, so we won't support them, yet
	if "(" in currname or "<" in currname:
		return ""

	if currname.startswith("`vtable for'"):
		currname = currname[12:]
	elif currname.endswith("::`vftable'"):
		currname = currname[6:-11]
	else:
		return ""

	# Anonymous namespace?
	if "'" in currname or "`" in currname:
		return ""
	return currname

def get_os():
	return OSData(OS_Linux if ida_nalt.get_root_filename().endswith(".so") else OS_Win)

UPDATE_TIME = time()
def update_window(s):
	global UPDATE_TIME
	currtime = time()
	if currtime - UPDATE_TIME > 0.2:
		ida_kernwin.replace_wait_box(s)
		UPDATE_TIME = currtime

def search_for_vtables():
	startea = OS.segm.start_ea
	ea = startea
	endea = OS.segm.end_ea
#	print(ea, endea)

	while ea < endea and ea != idc.BADADDR:
		name = is_vtable(ea)
		if name:
			update_window("Importing {} | {}%".format(name, floor((ea - startea) / float(endea - startea) * 100.0 * 10.0) / 10.0))
			ea = OS.parse_vtable(ea, name)
			continue
		ea = ida_bytes.next_head(ea, endea)

def main():
	global OS
	OS = get_os()
	search_for_vtables()

if __name__ == "__main__":
	main()