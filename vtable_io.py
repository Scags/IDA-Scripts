import idc
import idautils
import idaapi
import json
import ctypes
import time
import re

from dataclasses import dataclass

if idaapi.inf_is_64bit():
	ea_t = ctypes.c_uint64
	ptr_t = ctypes.c_int64
	get_ptr = idaapi.get_qword
	FF_PTR = idc.FF_QWORD
else:
	ea_t = ctypes.c_uint32
	ptr_t = ctypes.c_int32
	get_ptr = idaapi.get_dword
	FF_PTR = idc.FF_DWORD

# Calling these a lot so we'll speed up the invocations by manually implementing them here
def is_off(f): return (f & (idc.FF_0OFF|idc.FF_1OFF)) != 0
def is_code(f): return (f & idaapi.MS_CLS) == idc.FF_CODE
def has_any_name(f): return (f & idc.FF_ANYNAME) != 0
def is_ptr(f): return (f & idaapi.MS_CLS) == idc.FF_DATA and (f & idaapi.DT_TYPE) == FF_PTR

# Let's go https://www.blackhat.com/presentations/bh-dc-07/Sabanal_Yason/Paper/bh-dc-07-Sabanal_Yason-WP.pdf

_RTTICompleteObjectLocator_fields = [
		("signature",  ctypes.c_uint32), 					# signature
		("offset",  ctypes.c_uint32), 						# offset of this vtable in complete class (from top)
		("cdOffset",  ctypes.c_uint32), 					# offset of constructor displacement
		("pTypeDescriptor",  ctypes.c_uint32), 				# ref TypeDescriptor
		("pClassHierarchyDescriptor",  ctypes.c_uint32), 	# ref RTTIClassHierarchyDescriptor
	]

if idaapi.inf_is_64bit():
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


# Steps to retrieve vtables on Windows (MSVC):
#	1. Get RTTI's vftable (??_7type_info@@6B@)
#	2. Iterate over xrefs to, which are all TypeDescriptor objects
# 		a. Of course don't load up the function that uses it
# 	3. At each xref load up xrefs to again
# 		a. There should only be at least 2, the important ones are RTTICompleteObjectLocator's AKA COL (there can be more than 1)
# 		b. To discern which one is which, just see if there's a label at the address
# 			- If there is, then that one is RTTIClassHierarchyDescriptor, so skip it
# 	4. The current ea position at each xref should be at RTTICompleteObjectLocator::pTypeDescriptor, so subtract 12 to get to the beginning of the struct
# 	5. Find xrefs to each. There should only be one, and it should be its vtable
# 		a. Each COL has an offset which will shows where its vtable starts, so running too far over the table will be easier to detect
#
# Steps to retrieve vtables on Linux (GCC and maybe Clang)
#	1. Get RTTI's vftable (_ZTVN10__cxxabiv117__class_type_infoE, 
# 		_ZTVN10__cxxabiv120__si_class_type_infoE, and _ZTVN10__cxxabiv121__vmi_class_type_infoE)
# 	2. First, before doing anything, shove each xref of type_info object into some sort of structure
# 		a. There's no easy way to cheese discerning which xref is the actual vtable, unless we want to start parsing IDA comments
# 	3. Once each type_info object and their references are loaded, get the xrefs from each pVFTable
# 	4. There will probably be more than one xref.
# 		a. To discern which one is a vtable, if the xref lies in another type_info object, then it's not a vtable
# 		b. The remaining xref(s) is indeed a vtable

# Class for windows type info, helps organize things
@dataclass(frozen=True)
class WinTI(object):
	typedesc: int
	name: str
	cols: list[int]
	vtables: list[int]

# Class for function lists (what is held in the json)
@dataclass(frozen=True)
class FuncList:
	thisoffs: int
	funcs: list#[VFunc]

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

# Virtual class tree
class VClass(object):
	def __init__(self, *args, **kwargs):
		self.name = kwargs.get("name", "")
		# dict[classname, VClass]
		self.baseclasses = kwargs.get("baseclasses", {})
		# Same as Linux json, dict[thisoffs, funcs]
		self.vfuncs = kwargs.get("vfuncs", {})
		# Written to when writing to Windows, dict[thisoffs, [VFunc]]
		self.vfuncnames = kwargs.get("vfuncnames", {})
		# Exists solely to speed up checking for inherited functions
		self.postnames = set()

	def __str__(self):
		return f"{self.name} (baseclasses = {self.baseclasses}, vfuncs = {self.vfuncs})"

	def parse(self, colea, wintable):
		col = get_class_from_ea(RTTICompleteObjectLocator, colea)
		thisoffs = col.offset

		# Already parsed
		if self.name in wintable.keys():
			if thisoffs in wintable[self.name].vfuncs.keys():
				return


		# In 64-bit PEs, the COL references itself, remove this
		xrefs = list(idautils.XrefsTo(colea))
		if idaapi.inf_is_64bit():
			for n in range(len(xrefs)-1, -1, -1):
				if xrefs[n].frm == colea + RTTICompleteObjectLocator.pSelf.offset:
					del xrefs[n]

		if len(xrefs) != 1:
			print(f"[VTABLE IO] Multiple vtables point to same COL - {self.name} at {colea:#x}")
			return

		vtable = xrefs[0].frm + ctypes.sizeof(ea_t)
		self.vfuncs[thisoffs] = parse_vtable_addresses(vtable)

# TODO; This is created for each function in the json and for each function in each vtable
# This clearly does this for multiple of each function, so there needs to be a way to
# cache each function and reuse it for each vtable
# Possible pain point is differentiating between inheritedness
@dataclass
class VFunc:
	ea: int				# Address to this function
	vaddr: int 			# Address to this function's reference in its vtable
	mangledname: str
	inheritid: int
	name: str
	postname: str
	sname: str

	@staticmethod
	def create(ea=idc.BADADDR, mangledname="", inheritid=-1, vaddr=idc.BADADDR):
		name = ""
		postname = ""
		sname = ""
		if mangledname:
			name = idaapi.demangle_name(mangledname, idaapi.MNG_LONG_FORM) or mangledname
			if name:
				postname = get_func_postname(name)
				sname = postname.split("(")[0]
		return VFunc(ea, vaddr, mangledname, inheritid, name, postname, sname)

class VOptions(object):
	StringMethod = 1 << 0
	SkipMismatches = 1 << 1
	CommentReusedFunctions = 1 << 2

	DoNotExport = 0
	ExportNormal = 1
	ExportOnly = 2

# Form for script options
class VForm(idaapi.Form):

	def __init__(self):
		idaapi.Form.__init__(self, r"""STARTITEM 0
BUTTON YES* Go
BUTTON CANCEL Cancel
VTable IO
{FormChangeCb}
<#Browse#Select a file to import from                     :{iFileImport}>
           <##Import options##Parse type strings (for hashed type info):{rStringMethod}>    | <##Export options##Do not export:{rDoNotExport}>
           <Skip vtable size mismatches:{rSkipMismatches}>	                                | <Export to file:{rExportNormal}>
           <Comment reused functions:{rComment}>{cImportOptions}>		                    | <Export only (do not type functions):{rExportOnly}>{cExportOptions}>
<#Browse#Select a file to export to (ignored if unchecked):{iFileExport}>
		""", {
			"FormChangeCb": idaapi.Form.FormChangeCb(self.OnFormChange),
			"iFileImport": idaapi.Form.FileInput(open=True, value=idaapi.reg_read_string("vtable_io", "iFileImport", "*.json"), swidth=50),
			"cImportOptions": idaapi.Form.ChkGroupControl(
				("rStringMethod", "rSkipMismatches", "rComment"), value=idaapi.reg_read_int("vtable_io", VOptions.SkipMismatches | VOptions.CommentReusedFunctions, "cImportOptions")
			),
			"cExportOptions": idaapi.Form.RadGroupControl(
				("rDoNotExport", "rExportNormal", "rExportOnly"), value=idaapi.reg_read_int("vtable_io", VOptions.DoNotExport, "cExportOptions")
			),
			"iFileExport": idaapi.Form.FileInput(save=True, value=idaapi.reg_read_string("vtable_io", "iFileExport", "*.json"), swidth=50),
		})

	def OnFormChange(self, fid):
		# print(fid)
		return 1

	@staticmethod
	def init_options():
		f = VForm()
		f, _ = f.Compile()
		go = f.Execute()
		if not go:
			return None

		options = VOptions()
		for control in f.controls.keys():
			if control != "FormChangeCb":
				currval = getattr(f, control).value
				setattr(options, control, currval)
				if isinstance(currval, str):
					idaapi.reg_write_string("vtable_io", currval, control)
				elif isinstance(currval, int):
					idaapi.reg_write_int("vtable_io", currval, control)
				else:
					print(f"Unsupported type for {control} - {type(currval)}")

		f.Free()
		return options

OS_Linux = 0
OS_Win = 1

FUNCS = 0
EXPORTS = 0

VOPTIONS = None

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

def rva_to_ea(ea):
	if idaapi.inf_is_64bit():
		return idaapi.get_imagebase() + ea
	return ea

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

def parse_vtable_names(ea):
	funcs = []

	while ea != idc.BADADDR:
		# Using flags sped this up by a lot
		# Went from 4 secs to ~1.3
		flags = idaapi.get_full_flags(ea)
		if not is_off(flags) or not is_ptr(flags):
			break

		if idaapi.has_name(flags):
			break

		offs = get_ptr(ea)
		fflags = idaapi.get_full_flags(offs)
		if not idaapi.is_func(fflags):
			break

		name = idaapi.get_name(offs)
		funcs.append(name)

		ea = idaapi.next_head(ea, idc.BADADDR)
	return funcs

def parse_vtable_addresses(ea):
	funcs = []

	while ea != idc.BADADDR:
		flags = idaapi.get_full_flags(ea)
		if not is_off(flags) or not is_ptr(flags):
			break

		offs = get_ptr(ea)
		fflags = idaapi.get_full_flags(offs)
		if not has_any_name(fflags):
			break

#		if not idaapi.is_func(fflags):# or not idaapi.has_name(fflags):
		# Sometimes IDA doesn't think a function is a function
		# This is all CSteamWorksGameStatsUploader's fault :(
		if not is_code(fflags):
			break

		funcs.append(VFunc.create(ea=offs, vaddr=ea))

		ea = idaapi.next_head(ea, idc.BADADDR)
	return funcs

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
			print(f"[VTABLE IO] Invalid name at {tinfoxref.frm:#x}")
			continue

		classname = demangled[len("`typeinfo for'"):]
		for xref in idautils.XrefsTo(tinfoxref.frm, idaapi.XREF_DATA):
			if xref.frm not in tinfos.keys():
				# If address lies in a function
				if idaapi.is_func(idaapi.get_full_flags(xref.frm)):
					continue

				count += 1
				vtables[classname] = vtables.get(classname, []) + [xref.frm]

def read_vtables_linux():
	f = idaapi.ask_file(1, "*.json", "Select a file to export to")
	if not f:
		return
		
	WaitBox.show("Parsing typeinfo")

	# Step 1 and 2, crawl xrefs and stick the inherited class type infos into a structure
	# After this, we can run over the xrefs again and see which xrefs come from another structure
	# The remaining xrefs are either vtables or weird math in a function
	xreftinfos = {}

	def getparse(name, fn, quiet=False):
		tinfo = idc.get_name_ea_simple(name)
		if tinfo == idc.BADADDR and not quiet:
			print(f"[VTABLE IO] Type info {name} not found. Skipping...")
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
		print("[VTABLE IO] No type infos found. Are you sure you're in a C++ binary?")
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
	jsondata = parse_vtables(vtables)

	WaitBox.show("Writing to file")
	with open(f, "w") as f:
		json.dump(jsondata, f, indent=4, sort_keys=True)

def parse_ti(ea, tis):
	typedesc = ea
	flags = idaapi.get_full_flags(ea)
	if is_code(flags):
		return
	
	name = idc.get_name(ea)
	if not name:
		return

	# Pointer type
	# I have no idea what this is but it is not what we want
	if name.startswith("??_R0P"):
		return

	try:
		classname = idaapi.demangle_name(name, idaapi.MNG_SHORT_FORM)
		classname = classname.removeprefix("class ")
		classname = classname.removeprefix("struct TypeDescriptor ")
		classname = classname.removesuffix(" `RTTI Type Descriptor'")
		classname = classname.strip()
	except:
		print(f"[VTABLE IO] Invalid vtable name at {ea:#x}")
		return
	
	if classname in tis.keys():
		return

	cols = []
	vtables = []

	# Then figure out which xref is a/the COL
	for xref in idautils.XrefsTo(typedesc):
		ea = xref.frm
		flags = idaapi.get_full_flags(ea)

		# Dynamic cast
		if is_code(flags):
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
			print(f"[VTABLE IO] Possible COL is unknown at {ea:#x}. This may be an unreferenced vtable. Trying workaround...")
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
			print(f"[VTABLE IO] Invalid name at {ea:#x}. Possible unwind info. Ignoring...")
			continue

		# In 64-bit PEs, the COL references itself, remove this
		refs = list(idautils.XrefsTo(ea))
		if idaapi.inf_is_64bit():
			for n in range(len(refs)-1, -1, -1):
				if refs[n].frm == ea + RTTICompleteObjectLocator.pSelf.offset:
					del refs[n]

		# Now that we have the COL, we can use it to find the vtable that utilizes it and its thisoffs
		# We need to use this later because of overloads so we cache it in a list
		if len(refs) != 1:
			print(f"[VTABLE IO] Multiple vtables point to same COL - {name} at {ea:#x}")
			continue

		cols.append(ea)
		vtable = refs[0].frm + ctypes.sizeof(ea_t)
		vtables.append(vtable)

	# Can have RTTI without a vtable
	tis[classname] = WinTI(typedesc, classname, cols, vtables)


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

		print("[VTABLE IO] type_info not found. Are you sure you're in a C++ binary?")
		return None
	
	tis = {}

	# Step 2, get all xrefs to type_info
	# Get type descriptor
	for typedesc in idautils.XrefsTo(type_info):
		parse_ti(typedesc.frm, tis)

	# In some cases, the IDA either fails to reference some type descriptors with type_info
	# Not exactly sure why, but it lists the ea of type_info as a "hash" when in reality it isn't
	# A workaround for this is to parse type descriptor strings (".?AV*"), load up their references, and 
	# walk backwards to the start of what is supposed to be the type descriptor, and assure that
	# its DWORD is the type_info vtable
	# We also make this an optional feature because it's slow in older IDA versions and not necessarily needed
	# I only found this to be a problem in NMRIH, so it appears to be rare
	if VOPTIONS.cImportOptions & VOptions.StringMethod:
		WaitBox.show("Performing string parsing")
		string_method(type_info, tis)
	
	return tis

def string_method(type_info, tis):
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

		parse_ti(ea, tis)


def parse_vtables(vtables):
	jsondata = {}
	ptrsize = ctypes.sizeof(ea_t)
	for classname, tables in vtables.items():
		# We don't *need* to do any sort of sorting in Linux and can just capture the thisoffset
		# The Windows side of the script can organize later
		for ea in tables:
			thisoffs = get_ptr(ea - ptrsize)

			funcs = parse_vtable_names(ea + ptrsize)
			# Can be zero if there's an xref in the global offset table (.got) section
			# Fortunately the parse_vtable function doesn't grab anything from there
			if funcs:
				classdata = jsondata.get(classname, {})
				classdata[ptr_t(thisoffs).value] = funcs
				jsondata[classname] = classdata

	return jsondata

# See if the thunk is actually a thunk and jumps to
# a function in the vtable
def is_thunk(thunkfunc, targetfuncs):
	ea = thunkfunc.ea
	func = idaapi.get_func(ea)
	funcend = func.end_ea

#	if funcend - ea > 20:	# Highest I've seen is 13 opcodes but this works ig
#		return False

	addr = idc.next_head(ea, funcend)

	if addr == idc.BADADDR:
		return False

	b = idaapi.get_byte(addr)
	if b in (0xEB, 0xE9):
		insn = idaapi.insn_t()
		idaapi.decode_insn(insn, addr)
		jmpaddr = insn.Op1.addr
		return any(jmpaddr == i.ea for i in targetfuncs)

	return False

def build_export_table(linuxtables, wintables):
	# Table is built mainly for readability but having one that is actually parsable would
	# be a cool idea for the future
	exporttable = {}
	# Save Linux only tables for exporting too
	winless = {k: linuxtables[k] for k in linuxtables.keys() - wintables.keys()}
	global EXPORTS
	for classname, wintable in wintables.items():
		linuxtable = linuxtables.get(classname, None)
		if linuxtable is None:
			continue

		# Sort and int-ify Linux again
		newlinuxtable = [(abs(int(k)), v) for k, v in linuxtable.items()]
		newlinuxtable.sort(key=lambda x: x[0])

		exportnode = []
		purecalls = []
		for currlinuxitems, currwinitems in zip(newlinuxtable, wintable.items()):
			lthisoffs, ltable = currlinuxitems
			wthisoffs, wtable = currwinitems

			windiscovered = set()
			prepend = f"[L{lthisoffs}/W{wthisoffs}]"
			for i, mangledname in enumerate(ltable):
				# Save for later
				if mangledname.startswith("__cxa"):
					# print(f"Found purecall {classname}::{mangledname} at {i}")
					purecalls.append(i)
					continue

				winidx = -1
				for j, winfunc in enumerate(wtable):
					if mangledname == winfunc.mangledname:
						winidx = j
						windiscovered.add(j)
						break

				s = f"L{i}"
				if winidx != -1:
					s = f"{s:<8}W{winidx}"

				if not mangledname.startswith("sub_"):
					shortname = idaapi.demangle_name(mangledname, idaapi.MNG_SHORT_FORM) or "purecall"
				else:
					shortname = mangledname
				newprepend = f"{prepend:<20}{s:<8}"
				s = f"{newprepend:<36}{shortname}"
				exportnode.append(s)

			# Purecalls are a bit special
			# We can't just grab the Linux index and use it for Windows
			# So we 1: do this after everything else is done, and 2: find the first
			# Windows purecall after the last purecall we found for each one
			# in the Linux table
			# This is kinda hard to test edge cases, but we'll assume this works
			lastidx = 0
			for i in purecalls:
				winidx = -1
				for j, winfunc in enumerate(wtable[lastidx:]):
					if winfunc.mangledname == "__cxa_pure_virtual":
						winidx = j + lastidx
						break

				s = f"L{i}"
				if winidx != -1:
					s = f"{s:<8}W{winidx}"

				shortname = idaapi.demangle_name(mangledname, idaapi.MNG_SHORT_FORM) or "purecall"
				newprepend = f"{prepend:<20}{s:<8}"
				s = f"{newprepend:<36}{shortname}"
				exportnode.insert(i, s)
				lastidx = winidx+1
				windiscovered.add(winidx)

			# For thunks, figure out which Windows indices were not discovered and add them
			# Inherited table might be out of order but we favor Linux anyways
			for j, winfunc in enumerate(wtable):
				if j not in windiscovered:
					dummy = ""
					s = f"W{j}"

					shortname = idaapi.demangle_name(winfunc.mangledname, idaapi.MNG_SHORT_FORM) or "purecall"
					newprepend = f"{prepend:<20}{dummy:<8}{s:<8}"
					s = f"{newprepend:<36}{shortname}"
					exportnode.append(s)

		EXPORTS += 1
		exporttable[classname] = exportnode

	# Export Linux only tables
	for classname, linuxtable in winless.items():
		# Sort and int-ify Linux again
		newlinuxtable = [(abs(int(k)), v) for k, v in linuxtable.items()]
		newlinuxtable.sort(key=lambda x: x[0])
		exportnode = []
		for thisoffs, table in newlinuxtable:
			prepend = f"[L{thisoffs}]"
			for i, mangledname in enumerate(table):
				shortname = idaapi.demangle_name(mangledname, idaapi.MNG_SHORT_FORM) or "purecall"
				newprepend = f"{prepend:<20}L{i:<8}"
				s = f"{newprepend:<36}{shortname}"
				exportnode.append(s)

		EXPORTS += 1
		exporttable[classname] = exportnode
	return exporttable

def read_vtables_win(classname, ti, wintable, baseclasses):
	if classname in wintable.keys():
		return

	vclass = wintable.get(classname, VClass(name=classname, baseclasses=baseclasses))
	for colea in ti.cols:
		vclass.parse(colea, wintable)

	wintable[classname] = vclass

def read_tinfo_win(classname, ti, winti, wintable, baseclasses):
	# Strange cases where there is a base class descriptor with no vtable
	if classname not in winti.keys():
		return

	if classname in wintable.keys():
		return
	
	# No COLs, but we still keep the type in the wintable
	if not ti.cols:
		wintable[classname] = VClass(name=classname, baseclasses=baseclasses)
		return

	# So essentially we just run through each base class in the hierarchy descriptor 
	# and recursively parse the base classes of the base classes
	# Sort of like a reverse insertion sort only not really a sort
	for colea in ti.cols:
		col = get_class_from_ea(RTTICompleteObjectLocator, colea)
		hierarchydesc = get_class_from_ea(RTTIClassHierarchyDescriptor, rva_to_ea(col.pClassHierarchyDescriptor))
		numitems = hierarchydesc.numBaseClasses
		arraystart = rva_to_ea(hierarchydesc.pBaseClassArray)

		# Go backwards because we should start parsing from the basest base class
		for i in range(numitems - 1, -1, -1):
			offset = arraystart + i * ctypes.sizeof(ctypes.c_uint32)
			descea = rva_to_ea(idaapi.get_wide_dword(offset))
			parentname = idaapi.demangle_name(idaapi.get_name(descea), idaapi.MNG_SHORT_FORM)
			if not parentname:
				# Another undefining IDA moment
#				print(f"[VTABLE IO] Invalid parent name at {offset:#x}")
				typedesc = rva_to_ea(idaapi.get_wide_dword(descea))
				parentname = idaapi.demangle_name(idaapi.get_name(typedesc), idaapi.MNG_SHORT_FORM)

				# Should be impossible since this is the type descriptor
				if not parentname:
					print(f"[VTABLE IO] Invalid parent name at {offset:#x} - type descriptor at {typedesc:#x}")
					continue

				parentname = parentname.removeprefix("class ")
				parentname = parentname.removeprefix("struct TypeDescriptor ")
				parentname = parentname.removesuffix(" `RTTI Type Descriptor'")
			else:
				parentname = parentname[:parentname.find("::`RTTI Base Class Descriptor")]

			# End of the line
			if i == 0:
				read_vtables_win(classname, winti[parentname], wintable, baseclasses)
			elif parentname in winti.keys():
				read_tinfo_win(parentname, winti[parentname], winti, wintable, baseclasses)
				# Once again relying on dicts being ordered
				baseclasses[parentname] = wintable[parentname]

def gen_win_tables(winti):
	# So first we start looping windows typeinfos because
	# we're going to go from the COL -> ClassHierarchyDescriptor -> BaseClassArray
	# The reason why we're doing this is because of subclass overloads
	# For a history lesson, see https://github.com/Scags/IDA-Scripts/blob/125f1877a24da48062e62efcfb7d8a63e3bd939b/vtable_io.py#L251-L263
	# We're going to fix this by writing (and thus caching the names of) the baseclasses of classes first
	# This way, we'll be able to know the classname and the virtual functions contained therein, 
	# and thus we will know if there is an overload that exists in a subclass
	# This relies on the fact that dicts are ordered in Python 3.7+
	# If you're running Jiang Yang, either get a job or replace wintables with an OrderedDict

	# Same format as linuxtables
	# {classname: VClass(classname, {thisoffs: [vfunc...], ...}, ...})
	wintables = {}
	for classname, ti in winti.items():
		read_tinfo_win(classname, ti, winti, wintables, {})
	
	return wintables

def fix_windows_classname(classname):
	# Double pointers are spaced...
	classnamefix = classname.replace("* *", "**")

	# References/pointers that are const are spaced...
	classnamefix = classnamefix.replace("const &", "const&")
	classnamefix = classnamefix.replace("const *", "const*")

	# And true/false is instead replaced with 1/0
	def replacer(m):
		# Avoid replacing 1s and 0s that are a part of classnames
		# Thanks ChatGPT
		return re.sub(r"(?<=\W)1(?=\W)", "true", re.sub(r"(?<=\W)0(?=\W)", "false", m.group()))
	classnamefix = re.sub(r"<[^>]+>", replacer, classnamefix)

	# Other quirks are inline structs and templated enums
	# which are pretty much impossible to deduce
	return classnamefix

# Idk why but sometimes pointers have a mind of their own
def fix_windows_classname2(classname):
	return classname.replace(" *", "*")

def fix_win_overloads(linuxitems, winitems, vclass, functable):
	for i in range(min(len(linuxitems), len(winitems))):
		currfuncs = linuxitems[i].funcs
		vfuncs = []
		for u in range(len(currfuncs)):
			f = VFunc.create(mangledname=currfuncs[u])
			for j, baseclass in enumerate(vclass.baseclasses.values()):
				if f.postname in baseclass.postnames:
					f.inheritid = j
					break

				# Unbelievable hack right here
				# Looks like pointers are getting shoved next to their types instead of spaced sometimes
				# Not entirely sure what causes this.
				# CAI_BaseNPC::CanStandOn(CBaseEntity*) vs CBaseEntity::CanStandOn(CBaseEntity *)
				# Maybe it's the difference in the types of the pointers and this?
				trystr = f.postname
				breakout = False
				for k in range(trystr.count(" *")):
					trystr = trystr.replace(" *", "*", 1)
					if trystr in baseclass.postnames:
						f.inheritid = j
						f.postname = trystr
						breakout = True
						break

				if breakout:
					break

			vfuncs.append(f)

		# Remove Linux's extra dtor
		for u, f in enumerate(vfuncs):
			if "::~" in f.name:
				del vfuncs[u]
				break

		# Windows does overloads backwards, reverse them
		funcnameset = set()
		u = 0
		while u < len(vfuncs):
			f = vfuncs[u]

			if f.mangledname.startswith("__cxa"):# or f.mangledname.startswith("_ZThn") or f.mangledname.startswith("_ZTv"):
				u += 1
				continue

			if not f.name:
				u += 1
				continue

			# This is an overload, we take the function name here, and push it somewhere else
			if f.sname in funcnameset:
				# Find the first index of the overload
				firstidx = -1
				for k in range(u):
					if vfuncs[k].sname == f.sname:
						firstidx = k
						break

				if firstidx == -1:
					print(f"[VTABLE IO] An impossibility has occurred. \"{f.sname}\" ({f.mangledname}, {f.name}) is in funcnameset but there is no possible overload.")

				overloadfunc = vfuncs[firstidx]
				if overloadfunc.inheritid != f.inheritid:
					# Although this function is an overload, it was created in a subclass
					# So we don't move it
					u += 1
					continue

				# Remove the current func from the list
				del vfuncs[u]
				# And insert it into the first index
				vfuncs.insert(firstidx, f)
				u += 1
				continue

			funcnameset.add(f.sname)
			u += 1

		for f in vfuncs:
			vclass.postnames.add(f.postname)
		functable[linuxitems[i].thisoffs] = vfuncs

def thunk_dance(winitems, vclass, functable):
	# Now it's time for thunk dancing
	mainltable = functable[0]
	mainwtable = winitems[0].funcs
	for currlinuxitems, currwinitems in zip(functable.items(), winitems):
		thisoffs, ltable = currlinuxitems
		wtable = currwinitems.funcs
		if thisoffs == 0:
			continue

		# Remove any extra dtors from this table
		dtorcount = 0
		for i, f in enumerate(ltable):
			if "::~" in f.name:
				dtorcount += 1
				if dtorcount > 1:
					del ltable[i]
					break

		i = 0
		while i < len(mainltable):
			f = mainltable[i]
			if f.mangledname.startswith("__cxa"):
				i += 1
				continue

			# I shouldn't need to do this, but destructors are wonky
			if i == 0 and "::~" in f.name:
				i += 1
				continue

			if not f.postname:
				i += 1
				continue

			# Windows skips the vtable function if it's implementation is in the thunks
			# A way to check if this is true is to see which thunks are actually thunks
			# Then we just pop its name from the main table, since it's no longer there
			thunkidx = -1
			for u in range(len(ltable)):
				if ltable[u].postname == f.postname:
					thunkidx = u
					break

			if thunkidx != -1:
				try:
					# We can't exactly see if the possible thunk jumps to a certain function (mainwtable[i]) because
					# it's impossible to know what that function even is, so we instead check to see if
					# it jumps into any function in the main vtable which is good enough
					if not is_thunk(wtable[thunkidx], mainwtable):
						ltable[thunkidx] = mainltable[i]
						del mainltable[i]
						continue
				except:
					print(f"[VTABLE IO] Anomalous thunk: {vclass.name}::{f.postname}, mainwtable {len(mainwtable)} wtable {len(wtable)} thunkidx {thunkidx} thisoffs {thisoffs}")
					pass
			i += 1

		# Update current linux table
		functable[thisoffs] = ltable

	# Update main table
	functable[0] = mainltable

def prep_linux_vtables(linuxitems, winitems, vclass):
	functable = {}

	fix_win_overloads(linuxitems, winitems, vclass, functable)

	# No thunks, we are done
	if min(len(linuxitems), len(winitems)) == 1:
		return functable

	thunk_dance(winitems, vclass, functable)

	# Ready to write
	return functable

def merge_tables(functable, winitems):
	for items in zip(functable.items(), winitems):
		# Should probably make this unpacking/packing more efficient
		currlitems, currwitems = items
		_, ltable = currlitems
		wtable = currwitems.funcs

		for i, f in enumerate(ltable):
			targetname = f.mangledname
			# Purecall, which should already be handled on the Windows side
			if targetname.startswith("__cxa"):
				continue

			# Size mismatch, skip it
			try:
				currfunc = wtable[i]
			except:
				continue
			targetaddr = currfunc.ea

			flags = idaapi.get_full_flags(targetaddr)
			# Already typed
			if idaapi.has_name(flags):
				if VOPTIONS.cImportOptions & VOptions.CommentReusedFunctions:
					# If it's a Windows optimization (nullsubs, etc),
					# add a comment with the actual name
					# There's gotta be a way to rename the reference but not the function
					currmangledname = idaapi.get_name(targetaddr)
					currname = idaapi.demangle_name(currmangledname, idaapi.MNG_LONG_FORM)
					if not currname or currname != f.name:
						# Use short name for cmt since that's what IDA uses
						shortname = idaapi.demangle_name(f.mangledname, idaapi.MNG_SHORT_FORM)
						idaapi.set_cmt(currfunc.vaddr, shortname, False)
				continue

			func = idaapi.get_func(targetaddr)
			# Not actually a function somehow
			if not func:
				continue

			# A library function (should already have a name)
			if func.flags & idaapi.FUNC_LIB:
				continue

			idaapi.set_name(targetaddr, targetname, idaapi.SN_FORCE)
			global FUNCS
			FUNCS += 1

def compare_tables(wintables, linuxtables):
	functables = {}
	for classname, vclass in wintables.items():
		if not vclass.vfuncs:
			continue

		linuxtable = linuxtables.get(classname, {})
		if not linuxtable:
			# Some weird Windows quirks
			classnamefix = fix_windows_classname(classname)
			linuxtable = linuxtables.get(classnamefix, {})
			if not linuxtable:
				# Another very weird quirk
				classnamefix = fix_windows_classname2(classnamefix)
				linuxtable = linuxtables.get(classnamefix, {})
				if not linuxtable:
#					print(f"[VTABLE IO] {classname}{f' (tried {classnamefix})' if classname != classnamefix else ''} not found in Linux tables. Skipping...")
					continue

		winitems = list(FuncList(x[0], x[1]) for x in vclass.vfuncs.items())
		# Sort by thisoffs, smallest first
		winitems.sort(key=lambda x: x.thisoffs)

		# Convert the string thisoffs to int
		# Linux thisoffses are negative, abs them
		linuxitems = list(FuncList(abs(int(x[0])), x[1]) for x in zip([abs(int(i)) for i in linuxtable.keys()], linuxtable.values()))
		linuxitems.sort(key=lambda x: x.thisoffs)

		# If there's a size mismatch (very rare), then most likely IDA failed to analyze
		# A certain vtable, so we can't continue given the high probability of catastrophich failure
		if len(winitems) != len(linuxitems):
			print(f"[VTABLE IO] {classname} vtable # mismatch - L{len(linuxitems)} W{len(winitems)}. Skipping...")
			continue

		functable = prep_linux_vtables(linuxitems, winitems, vclass)

		skip = False
		for items in zip(functable.items(), winitems):
			currlinuxitems, currwinitems = items
			thisoffs, ltable = currlinuxitems
			if len(ltable) != len(currwinitems.funcs):
				print(f"[VTABLE IO] WARNING: {vclass.name} vtable [W{currwinitems.thisoffs}/L{thisoffs}] may be wrong! L{len(ltable)} - W{len(currwinitems.funcs)} = {len(ltable) - len(currwinitems.funcs)}", end="")
				if VOPTIONS.cImportOptions & VOptions.SkipMismatches:
					print(". Skipping...")
					skip = True
					break
				else:
					print()

		if skip:
			continue

		functables[classname] = functable

		# Write!
		if VOPTIONS.cExportOptions != VOptions.ExportOnly:
			merge_tables(functable, winitems)

	return functables

def write_vtables():
	WaitBox.show("Importing file")
	linuxtables = None
	try:
		with open(VOPTIONS.iFileImport) as f:
			linuxtables = json.load(f)
	except FileNotFoundError as e:
		print(f"[VTABLE IO] File {VOPTIONS.iFileImport} not found.")
		return

	if not linuxtables:
		return

	WaitBox.show("Parsing Windows typeinfo")
	winti = read_ti_win()
	if winti is None:
		return
	
	WaitBox.show("Generating windows vtables")
	wintables = gen_win_tables(winti)

	if not wintables:
		return

	WaitBox.show("Comparing vtables")
	functables = compare_tables(wintables, linuxtables)

	if VOPTIONS.cExportOptions in (VOptions.ExportOnly, VOptions.ExportNormal):
		if VOPTIONS.iFileExport is None or VOPTIONS.iFileExport == "*.json":
			print("[VTABLE IO] No export file specified.")
			return

		WaitBox.show("Writing to file")
		exporttable = build_export_table(linuxtables, functables)
		with open(VOPTIONS.iFileExport, "w") as f:
			json.dump(exporttable, f, indent=4, sort_keys=True)


def main():
	os = get_os()
	if os == -1:
		print(f"Unsupported OS?: {idaapi.get_file_type_name()}")
		idaapi.beep()
		return

	try:
		if os == OS_Linux:
			read_vtables_linux()
			print("Done!")
		elif os == OS_Win:
			global VOPTIONS
			VOPTIONS = VForm.init_options()
			if not VOPTIONS:
				return
			
			write_vtables()
			if FUNCS:
				print(f"[VTABLE IO] Successfully typed {FUNCS} virtual functions")
			else:
				print("[VTABLE IO] No functions were typed")

			if EXPORTS:
				print(f"[VTABLE IO] Successfully exported {EXPORTS} virtual tables")
			
			if FUNCS == 0 and EXPORTS == 0:
				idaapi.beep()
	except:
		import traceback
		traceback.print_exc()
		print("Please file a bug report with supporting information at https://github.com/Scags/IDA-Scripts/issues")
		idaapi.beep()

	WaitBox.hide()

# import cProfile
# cProfile.run("main()", "vtable_io.prof")
main()