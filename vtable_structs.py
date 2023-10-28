import idc
import idautils
import idaapi
import ctypes
import time

from dataclasses import dataclass

OS_Linux = 0
OS_Win = 1

if idc.__EA64__:
	ea_t = ctypes.c_uint64
	ptr_t = ctypes.c_int64
	get_ptr = idaapi.get_qword
	FF_PTR = idc.FF_QWORD
else:
	ea_t = ctypes.c_uint32
	ptr_t = ctypes.c_int32
	get_ptr = idaapi.get_dword
	FF_PTR = idc.FF_DWORD

def is_ptr(f): return (f & idaapi.MS_CLS) == idc.FF_DATA and (f & idaapi.DT_TYPE) == FF_PTR
def is_off(f): return (f & (idc.FF_0OFF|idc.FF_1OFF)) != 0


_RTTICompleteObjectLocator_fields = [
		("signature",  ctypes.c_uint32), 					# signature
		("offset",  ctypes.c_uint32), 						# offset of this vtable in complete class (from top)
		("cdOffset",  ctypes.c_uint32), 					# offset of constructor displacement
		("pTypeDescriptor",  ctypes.c_uint32), 				# ref TypeDescriptor
		("pClassHierarchyDescriptor",  ctypes.c_uint32), 	# ref RTTIClassHierarchyDescriptor
	]

if idc.__EA64__:
	_RTTICompleteObjectLocator_fields.append(("pSelf", ctypes.c_uint32)) # ref to object's base

class RTTICompleteObjectLocator(ctypes.Structure):
	_fields_ = _RTTICompleteObjectLocator_fields


class TypeDescriptor(ctypes.Structure):
	_fields_ = [
		("pVFTable", ctypes.c_uint32), 						# reference to RTTI's vftable
		("spare", ctypes.c_uint32), 						# internal runtime reference
		("name", ctypes.c_uint8), 							# type descriptor name (no varstruct needed since we don't use this)
	]


class RTTIClassHierarchyDescriptor(ctypes.Structure):
	_fields_ = [
		("signature", ctypes.c_uint32), 					# signature
		("attribs", ctypes.c_uint32), 						# attributes
		("numBaseClasses", ctypes.c_uint32), 				# # of items in the array of base classes
		("pBaseClassArray", ctypes.c_uint32), 				# ref BaseClassArray
	]


class RTTIBaseClassDescriptor(ctypes.Structure):
	_fields_ = [
		("pTypeDescriptor", ctypes.c_uint32),				# ref TypeDescriptor
		("numContainedBases", ctypes.c_uint32),				# # of sub elements within base class array
		("mdisp", ctypes.c_uint32),  						# member displacement
		("pdisp", ctypes.c_uint32),							# vftable displacement
		("vdisp", ctypes.c_uint32), 						# displacement within vftable
		("attributes", ctypes.c_uint32), 					# base class attributes
		("pClassDescriptor", ctypes.c_uint32), 				# ref RTTIClassHierarchyDescriptor
	]


class base_class_type_info(ctypes.Structure):
	_fields_ = [
		("basetype", ea_t), 								# Base class type
		("offsetflags", ea_t), 								# Offset and info
	]


class class_type_info(ctypes.Structure):
	_fields_ = [
		("pVFTable", ea_t), 								# reference to RTTI's vftable (__class_type_info)
		("pName", ea_t), 									# ref to type name
	]

# I don't think this is right, but every case I found looked to be correct
# This might be a vtable? IDA sometimes says it is but not always
# Plus sometimes the flags member is 0x1, so it's not a thisoffs. Weird
class pointer_type_info(class_type_info):
	_fields_ = [
		("flags", ea_t),									# Flags or something else
		("pType", ea_t),									# ref to type
	]

class si_class_type_info(class_type_info):
	_fields_ = [
		("pParent", ea_t), 									# ref to parent type
	]

class vmi_class_type_info(class_type_info):
	_fields_ = [
		("flags", ctypes.c_uint32), 						# flags
		("basecount", ctypes.c_uint32), 					# # of base classes
		("pBaseArray", base_class_type_info), 				# array of BaseClassArray
	]

def create_vmi_class_type_info(ea):
	bytestr = idaapi.get_bytes(ea, ctypes.sizeof(vmi_class_type_info))
	tinfo = vmi_class_type_info.from_buffer_copy(bytestr)

	# Since this is a varstruct, we create a dynamic class with the proper size and type and return it instead
	class vmi_class_type_info_dynamic(class_type_info):
		_fields_ = [
			("flags", ctypes.c_uint32),
			("basecount", ctypes.c_uint32),
			("pBaseArray", base_class_type_info * tinfo.basecount),
		]
	
	return vmi_class_type_info_dynamic

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
STRUCTS = 0

class InfoCache(object):
	tinfos = {}
	vfuncs = {}

# Class for windows type info, helps organize things
@dataclass(frozen=True)
class WinTI(object):
	typedesc: int
	name: str
	cols: list[int]
	vtables: list[int]

@dataclass
class VFuncRef:
	ea: int				# Address to this function
	mangledname: str
	name: str
	postname: str
	sname: str

	@staticmethod
	def create(ea=idc.BADADDR, mangledname=""):
		if InfoCache.vfuncs.get(ea):
			return InfoCache.vfuncs[ea]

		name = ""
		postname = ""
		sname = ""
		if mangledname:
			name = idaapi.demangle_name(mangledname, idaapi.MNG_SHORT_FORM)
			if name:
				postname = get_func_postname(name)
				sname = postname.split("(")[0]
			else:
				postname = mangledname
				sname = mangledname

		vfunc = VFuncRef(ea, mangledname, name, postname, sname)
		InfoCache.vfuncs[ea] = vfunc
		return vfunc

@dataclass(frozen=True)
class VFunc:
	funcref: VFuncRef
	vaddr: int 			# Address to this function's reference in its vtable

	@staticmethod
	def create(vaddr):
		ea = get_ptr(vaddr)
		ref = InfoCache.vfuncs.get(ea, VFuncRef.create(ea=ea, mangledname=idaapi.get_name(ea)))
		return VFunc(ref, vaddr)


def get_os():
	ftype = idaapi.get_file_type_name()
	if "ELF" in ftype:
		return OS_Linux
	elif "PE" in ftype:
		return OS_Win
	return -1

# Read a ctypes class from an ea
def get_class_from_ea(classtype, ea):
	bytestr = idaapi.get_bytes(ea, ctypes.sizeof(classtype))
	return classtype.from_buffer_copy(bytestr)

def add_struc_ex(name):
	strucid = idaapi.get_struc_id(name)
	if strucid == idc.BADADDR:
		strucid = idaapi.add_struc(idc.BADADDR, name)

	return strucid

# Anything past Classname::
# Thank you CTFPlayer::SOCacheUnsubscribed...
def get_func_postname(name):
	retname = name
	template = 0
	iterback = 0
	for i, c in enumerate(retname):
		if c == "<":
			template += 1
		elif c == ">":
			template -= 1
		# Find ( and break if we're not in a template
		elif c == "(" and template == 0:
			iterback = i
			break

	# Run backwards from ( until we hit a ::
	for i in range(iterback, -1, -1):
		if retname[i] == ":":
			retname = retname[i+1:]
			break

	return retname

def rva_to_ea(ea):
	if idc.__EA64__:
		return idaapi.get_imagebase() + ea
	return ea

def parse_si_tinfo(ea, tinfos):
	for xref in idautils.XrefsTo(ea):
		tinfo = get_class_from_ea(si_class_type_info, xref.frm)
		tinfos[xref.frm + si_class_type_info.pParent.offset] = tinfo.pParent


def parse_pointer_tinfo(ea, tinfos):
	for xref in idautils.XrefsTo(ea):
		tinfo = get_class_from_ea(pointer_type_info, xref.frm)
		tinfos[xref.frm + pointer_type_info.pType.offset] = tinfo.pType


def parse_vmi_tinfo(ea, tinfos):
	for xref in idautils.XrefsTo(ea):
		tinfotype = create_vmi_class_type_info(xref.frm)
		tinfo = get_class_from_ea(tinfotype, xref.frm)

		for i in range(tinfo.basecount):
			offset = vmi_class_type_info.pBaseArray.offset + i * ctypes.sizeof(base_class_type_info)
			basetinfo = get_class_from_ea(base_class_type_info, xref.frm + offset)
			tinfos[xref.frm + offset + base_class_type_info.basetype.offset] = basetinfo.basetype
			
def get_tinfo_vtables(ea, tinfos, vtables):
	if ea == idc.BADADDR:
		return

	for tinfoxref in idautils.XrefsTo(ea, idaapi.XREF_DATA):
		count = 0
		mangled = idaapi.get_name(tinfoxref.frm)
		demangled = idc.demangle_name(mangled, idaapi.MNG_LONG_FORM)
		if demangled is None:
			print(f"[VTABLE STRUCTS] Invalid name at {tinfoxref.frm:#x}")
			continue

		classname = demangled[len("`typeinfo for'"):]
		for xref in idautils.XrefsTo(tinfoxref.frm, idaapi.XREF_DATA):
			if xref.frm not in tinfos.keys():
				# If address lies in a function
				if idaapi.is_func(idaapi.get_full_flags(xref.frm)):
					continue

				count += 1
				vtables[classname] = vtables.get(classname, []) + [xref.frm]


def get_tinfo_vtables(ea, tinfos, vtables):
	if ea == idc.BADADDR:
		return

	for tinfoxref in idautils.XrefsTo(ea, idaapi.XREF_DATA):
		count = 0
		mangled = idaapi.get_name(tinfoxref.frm)
		demangled = idc.demangle_name(mangled, idaapi.MNG_LONG_FORM)
		if demangled is None:
			print(f"[VTABLE STRUCTS] Invalid name at {tinfoxref.frm:#x}")
			continue

		classname = demangled[len("`typeinfo for'"):]
		for xref in idautils.XrefsTo(tinfoxref.frm, idaapi.XREF_DATA):
			if xref.frm not in tinfos.keys():
				# If address lies in a function
				if idaapi.is_func(idaapi.get_full_flags(xref.frm)):
					continue

				count += 1
				vtables[classname] = vtables.get(classname, []) + [xref.frm]


def parse_vtables(vtables):
	jsondata = {}
	ptrsize = ctypes.sizeof(ea_t)
	for classname, tables in vtables.items():
		# We don't *need* to do any sort of sorting in Linux and can just capture the thisoffset
		# The Windows side of the script can organize later
		for ea in tables:
			thisoffs = get_ptr(ea - ptrsize)

			funcs = parse_vtable(ea + ptrsize)
			# Can be zero if there's an xref in the global offset table (.got) section
			# Fortunately the parse_vtable function doesn't grab anything from there
			if funcs:
				classdata = jsondata.get(classname, {})
				classdata[ptr_t(thisoffs).value] = funcs
				jsondata[classname] = classdata

	return jsondata

def parse_vtable(ea):
	funcs = []

	while ea != idc.BADADDR:
		# Using flags sped this up by a lot
		# Went from 4 secs to ~1.3
		flags = idaapi.get_full_flags(ea)
		if not is_off(flags) or not is_ptr(flags):
			break

		if get_os() == OS_Linux and idaapi.has_name(flags):
			break

		offs = get_ptr(ea)
		fflags = idaapi.get_full_flags(offs)
		if not idaapi.is_code(fflags):
			break

		if get_os() == OS_Win and not idaapi.has_any_name(fflags):
			break

		vfunc = VFunc.create(ea)
		# Invalid name, so this can be a "sub_", purecall, or an optimized function
		# So to keep vtable_io compat, we grab the comment instead and update the names
		if not vfunc.funcref.name:
			cmt = idaapi.get_cmt(ea, False)
			if cmt and "::" in cmt:
				vfunc.funcref.mangledname = None
				vfunc.funcref.name = cmt
				vfunc.funcref.postname = get_func_postname(vfunc.funcref.name)
				vfunc.funcref.sname = vfunc.funcref.postname.split("(")[0]

		funcs.append(vfunc)

		ea = idaapi.next_head(ea, idc.BADADDR)
	return funcs

def calc_member_tinfo(vfunc):
	cached = InfoCache.tinfos.get(vfunc.funcref.ea, None)
	if cached is not None:
		return cached

	# Get the type info of the function if it's present
	# In Windows, you can't get the actual tinfo so you can only guess
	# and use the rudimentary type info
	tinfo = idaapi.tinfo_t()
	if not idaapi.get_tinfo(tinfo, vfunc.funcref.ea):
		if idaapi.guess_tinfo(tinfo, vfunc.funcref.ea) == idaapi.GUESS_FUNC_FAILED:
			tinfo = None

	if tinfo is not None:
		tinfo.create_ptr(tinfo)
	
	InfoCache.tinfos[vfunc.funcref.ea] = tinfo
	return tinfo


def create_structs(data):
	# Now this is an awesome API function that we most certainly need
	idaapi.begin_type_updating(idaapi.UTP_STRUCT)

	for classname, vtables in data.items():
		classstrucid = add_struc_ex(classname)
		classstruc = idaapi.get_struc(classstrucid)
		for thisoffs, vfuncs in vtables.items():
			thisoffs = abs(thisoffs)
			postfix = f"_{thisoffs:04X}" if thisoffs != 0 else ""
			structype = f"{classname}{postfix}{idaapi.VTBL_SUFFIX}"
			structype = idaapi.validate_name(structype, idaapi.VNT_TYPE, idaapi.SN_IDBENC)

			vtablestrucid = add_struc_ex(structype)
			vtablestruc = idaapi.get_struc(vtablestrucid)
			for i, vfunc in enumerate(vfuncs):
				offs = i * ctypes.sizeof(ea_t)
				targetname = vfunc.funcref.sname

				currmem = idaapi.get_member(vtablestruc, offs)
				if currmem:
					# memname = idaapi.get_member_name(currmem.id)
					# # Can have a postfix so we use in operator
					# if targetname in memname:
					# 	if not currmem.has_ti():
					# 		tinfo = calc_member_tinfo(vfunc)
					# 		if tinfo is not None:
					# 			idaapi.set_member_tinfo(vtablestruc, currmem, 0, tinfo, 0)
					# 	continue

					# # Sadly if you reorganize a vtable and move a function up, this will fail
					# # and you'll have an unneeded postfix
					# if not idaapi.set_name(currmem.id, targetname, idaapi.SN_NOCHECK):
					# 	newname = f"{targetname}_{offs:x}"
					# 	if not idaapi.set_name(currmem.id, newname, idaapi.SN_NOCHECK):
					# 		print(f"Failed to set name for {classname}::{vfunc.funcref.sname} ({targetname}) at offset {offs:#x}")
					# 		continue

					# tinfo = calc_member_tinfo(vfunc)
					# if tinfo is not None:
					# 	idaapi.set_member_tinfo(vtablestruc, currmem, 0, tinfo, 0)
					continue

				else:
					opinfo = idaapi.opinfo_t()
					# I don't think this does anything
					opinfo.ri.flags = idaapi.REF_OFF64 if idc.__EA64__ else idaapi.REF_OFF32
					opinfo.ri.target = vfunc.funcref.ea
					opinfo.ri.base = 0
					opinfo.ri.tdelta = 0

					serr = idaapi.add_struc_member(vtablestruc, targetname, offs, FF_PTR|idc.FF_0OFF, opinfo, ctypes.sizeof(ea_t))
					# Failed, so there was either an invalid name or a name collision
					if serr == idaapi.STRUC_ERROR_MEMBER_NAME:
						targetname = idaapi.validate_name(targetname, idaapi.VNT_IDENT, idaapi.SN_IDBENC)
						serr = idaapi.add_struc_member(vtablestruc, targetname, offs, FF_PTR|idc.FF_0OFF, opinfo, ctypes.sizeof(ea_t))
						if serr == idaapi.STRUC_ERROR_MEMBER_NAME:
							targetname = f"{targetname}_{offs:X}"
							serr = idaapi.add_struc_member(vtablestruc, targetname, offs, FF_PTR|idc.FF_0OFF, opinfo, ctypes.sizeof(ea_t))

					if serr != idaapi.STRUC_ERROR_MEMBER_OK:
						print(vtablestruc, vtablestrucid)
						print(f"Failed to add member {classname}::{vfunc.funcref.sname} ({targetname}) at offset {offs:#x} -> {serr}")
						continue

					tinfo = calc_member_tinfo(vfunc)
					if tinfo is not None:
						mem = idaapi.get_member(vtablestruc, offs)
						idaapi.set_member_tinfo(vtablestruc, mem, 0, tinfo, 0)

			vmember = idaapi.get_member(classstruc, thisoffs)
			if not vmember:
				if idaapi.add_struc_member(classstruc, f"{idaapi.VTBL_MEMNAME}{postfix}", thisoffs, idc.FF_DATA | FF_PTR, None, ctypes.sizeof(ea_t)) == idaapi.STRUC_ERROR_MEMBER_OK:
					global STRUCTS
					STRUCTS += 1
					tinfo = idaapi.tinfo_t()
					if idaapi.guess_tinfo(tinfo, vtablestrucid) != idaapi.GUESS_FUNC_FAILED:
						mem = idaapi.get_member(classstruc, thisoffs)
						tinfo.create_ptr(tinfo)
						idaapi.set_member_tinfo(classstruc, mem, 0, tinfo, 0)

def read_vtables_linux():
	WaitBox.show("Parsing typeinfo")

	# Step 1 and 2, crawl xrefs and stick the inherited class type infos into a structure
	# After this, we can run over the xrefs again and see which xrefs come from another structure
	# The remaining xrefs are either vtables or weird math in a function
	xreftinfos = {}

	def getparse(name, fn, quiet=False):
		tinfo = idc.get_name_ea_simple(name)
		if tinfo == idc.BADADDR and not quiet:
			print(f"[VTABLE STRUCTS] Type info {name} not found. Skipping...")
			return None

		if fn is not None:
			fn(tinfo, xreftinfos)
		return tinfo

	# Don't need to parse base classes
	tinfo = getparse("_ZTVN10__cxxabiv117__class_type_infoE", None)	
	tinfo_pointer = getparse("_ZTVN10__cxxabiv119__pointer_type_infoE", parse_pointer_tinfo, True)
	tinfo_si = getparse("_ZTVN10__cxxabiv120__si_class_type_infoE", parse_si_tinfo)	
	tinfo_vmi = getparse("_ZTVN10__cxxabiv121__vmi_class_type_infoE", parse_vmi_tinfo)
	
	if len(xreftinfos) == 0:
		print("[VTABLE STRUCTS] No type infos found. Are you sure you're in a C++ binary?")
		return

	# Step 3, crawl xrefs to again and if the xref is not in the type info structure, then it's a vtable
	WaitBox.show("Discovering vtables")
	vtables = {}
	get_tinfo_vtables(tinfo, xreftinfos, vtables)
	get_tinfo_vtables(tinfo_pointer, xreftinfos, vtables)
	get_tinfo_vtables(tinfo_si, xreftinfos, vtables)
	get_tinfo_vtables(tinfo_vmi, xreftinfos, vtables)

	# Now, we have a list of vtables and their respective classes
	WaitBox.show("Parsing vtables")
	data = parse_vtables(vtables)

	WaitBox.show("Creating structs")
	create_structs(data)

def parse_ti(ea, tis):
	typedesc = ea
	flags = idaapi.get_full_flags(ea)
	if idaapi.is_code(flags):
		return

	try:
		classname = idaapi.demangle_name(idc.get_name(ea), idaapi.MNG_SHORT_FORM)
		classname = classname.removeprefix("class ")
		classname = classname.removeprefix("struct TypeDescriptor ")
		classname = classname.removesuffix(" `RTTI Type Descriptor'")
	except:
		print(f"[VTABLE STRUCTS] Invalid vtable name at {ea:#x}")
		return

	if classname in tis.keys():
		return

	vtables = []

	# Then figure out which xref is a/the COL
	for xref in idautils.XrefsTo(typedesc):
		ea = xref.frm
		flags = idaapi.get_full_flags(ea)

		# Dynamic cast
		if idaapi.is_code(flags):
			continue

		name = idaapi.get_name(ea)
		# Class type descriptor and/or random global data
		# Kind of a hack but let's assume no one will rename these
		if name and (name.startswith("??_R1") or name.startswith("off_")):
			continue

		ea -= 4
		name = idaapi.get_name(ea)
		# Catchable types
		if name and name.startswith("__CT"):
			continue

		# COL
		ea -= 8
		workaround = False
		if idaapi.is_unknown(idaapi.get_full_flags(ea)):
			print(f"[VTABLE STRUCTS] Possible COL is unknown at {ea:#x}. This may be an unreferenced vtable. Trying workaround...")
			# This might be a bug with IDA, but sometimes the COL isn't analyzed
			# If there's still a reference, then we can still trace back
			# If there is a list of functions (or even just one), then it's probably a vtable, 
			# but we'll still warn the user that it might be garbage
			refs = list(idautils.XrefsTo(ea))
			if len(refs) == 1:
				vtable = refs[0].frm + ctypes.sizeof(ea_t)
				tryfunc = get_ptr(vtable + ctypes.sizeof(ea_t))
				funcflags = idaapi.get_full_flags(tryfunc)
				if idaapi.is_func(funcflags):
					print(f" - Workaround successful. Please assure that {vtable:#x} is a vtable.")
					workaround = True

			if not workaround:
				print(" - Workaround failed. Skipping...")
				continue

		name = idaapi.get_name(ea)
		if not workaround and (not name or not name.startswith("??_R4")):
			print(f"[VTABLE STRUCTS] Invalid name at {ea:#x}. Possible unwind info. Ignoring...")
			continue

		# In 64-bit PEs, the COL references itself, remove this
		refs = list(idautils.XrefsTo(ea))
		if idc.__EA64__:
			for n in range(len(refs)-1, -1, -1):
				if refs[n].frm == ea + RTTICompleteObjectLocator.pSelf.offset:
					del refs[n]

		# Now that we have the COL, we can use it to find the vtable that utilizes it and its thisoffs
		if len(refs) != 1:
			print(f"[VTABLE STRUCTS] Multiple vtables point to same COL - {name} at {ea:#x}")
			continue

		vtable = refs[0].frm + ctypes.sizeof(ea_t)
		thisoffs = idaapi.get_dword(ea + RTTICompleteObjectLocator.offset.offset)
		vtables.append((thisoffs, vtable))

	# Can have RTTI without a vtable
	tis[classname] = {thisoffs: parse_vtable(vaddr) for thisoffs, vaddr in vtables}

def string_method(type_info, vtabledata):
	for string in idautils.Strings():
		sstr = str(string)
		if not sstr.startswith(".?AV"):
			continue

		ea = string.ea
		ea -= TypeDescriptor.name.offset
		trytinfo = rva_to_ea(idaapi.get_wide_dword(ea))
		# This is a weird string that isn't a part of a type descriptor
		if trytinfo != type_info:
			continue

		parse_ti(ea, vtabledata)

def read_ti_win():
	# Step 1, get the vftable of type_info
	type_info = idc.get_name_ea_simple("??_7type_info@@6B@")
	if type_info == idc.BADADDR:
		# If type_info doesn't exist as a label, we might still be able to snipe it with the string method
		strings = list(idautils.Strings())
		for s in strings:
			if str(s) == ".?AVtype_info@@":
				ea = s.ea - TypeDescriptor.name.offset
				type_info = rva_to_ea(idaapi.get_wide_dword(ea))

		if type_info == idc.BADADDR:
			print("[VTABLE STRUCTS] type_info not found. Are you sure you're in a C++ binary?")
			return None
	
	vtabledata = {}

	# Step 2, get all xrefs to type_info
	# Get type descriptor
	for typedesc in idautils.XrefsTo(type_info):
		parse_ti(typedesc.frm, vtabledata)

	# In some cases, the IDA either fails to reference some type descriptors with type_info
	# Not exactly sure why, but it lists the ea of type_info as a "hash" when in reality it isn't
	# A workaround for this is to parse type descriptor strings (".?AV*"), load up their references, and 
	# walk backwards to the start of what is supposed to be the type descriptor, and assure that
	# its DWORD is the type_info vtable
	# I only found this to be a problem in NMRIH, so it appears to be rare
	WaitBox.show("Performing string parsing")
	string_method(type_info, vtabledata)
	
	return vtabledata

def read_vtables_win():
	WaitBox.show("Parsing Windows typeinfo")
	data = read_ti_win()

	if data is None:
		return

	WaitBox.show("Creating structs")
	create_structs(data)

def main():
	os = get_os()
	try:
		if os == OS_Linux:
			read_vtables_linux()
		elif os == OS_Win:
			read_vtables_win()
		else:
			print(f"Unsupported OS?: {idaapi.get_file_type_name()}")
			idaapi.beep()
		
		if STRUCTS:
			print(f"Successfully imported {STRUCTS} virtual structures")
		else:
			print("No virtual structures imported")
			idaapi.beep()
	except:
		import traceback
		traceback.print_exc()
		print("Please file a bug report with supporting information at https://github.com/Scags/IDA-Scripts/issues")
		idaapi.beep()

	idaapi.end_type_updating(idaapi.UTP_STRUCT)
	WaitBox.hide()

# import cProfile
# cProfile.run("main()", "vtable_structs.prof")
main()
