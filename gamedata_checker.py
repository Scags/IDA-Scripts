import idautils
import idaapi
import idc
import vdf

from sys import version_info

OS_Linux = 0
OS_Win = 1

def get_os():
	ftype = idaapi.get_file_type_name()
	if "PE" in ftype:
		return OS_Win
	elif "ELF" in ftype:
		return OS_Linux
	return -1

def osstr(os):
	if os == OS_Linux:
		return "linux"
	elif os == OS_Win:
		return "windows"
	return "unknown"

def checksig(sig):
	if sig[0] == '@':
		# Just check for existence of this mangled name
		return idc.get_name_ea_simple(sig[1:]) != idc.BADADDR
	
	sig = sig.replace(r"\x", " ").replace("2A", "?").replace("2a", "?").replace("\\", "").strip()

	# Get the first segment that is executable to use its addresses for parse_binpat_str
	endea = idc.BADADDR
	for segea in idautils.Segments():
		s = idaapi.getseg(segea)
		if s.perm & idaapi.SEGPERM_EXEC:
			segstart = segea
			# Set the end ea to the end of the last executable segment
			# Speed isn't as important in this script, so reading any extra X
			# segments is fine
			if endea == idc.BADADDR or endea < segstart + s.size():
				endea = segstart + s.size()

	count = 0
	addr = 0
	addr = idaapi.find_binary(addr, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
	while count < 2 and addr != idc.BADADDR:
		count = count + 1
		if count > 1:
			break
		addr = idaapi.find_binary(addr, endea, sig, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)

	return count == 1

	# bin_search3 breaks after 15 or so bytes or something, idk man
	# binpat = idaapi.compiled_binpat_vec_t()
	# idaapi.parse_binpat_str(binpat, segstart, sig, 16, idaapi.get_default_encoding_idx(idaapi.get_encoding_bpu_by_name("UTF-8")))

	# count = 0
	# addr = 0
	# addr, _ = idaapi.bin_search3(addr, endea, binpat, idaapi.BIN_SEARCH_FORWARD)
	# while addr != idc.BADADDR:
	# 	count += 1
	# 	if count > 1:
	# 		break

	# 	# +1 because the search finds itself
	# 	addr, _ = idaapi.bin_search3(addr + 1, endea, binpat, idaapi.BIN_SEARCH_FORWARD)

	# return count == 1

def get_bcompat_items(d):
	return d.iteritems() if version_info[0] <= 2 else d.items()

# Unfortunately I don't care too much about overtly complex gamedata files
# If you have multiple #default's in you first subsection or you have #default
# anywhere else other than that first subsection, you're SOL. Sorry Silvers :c
def get_gamedir(kv):
	# If we've got multiple games supported, let's just ask
	if len(kv.items()) > 1:
		gamedir = idaapi.ask_str("", 0, "There are multiple games supported by this file. Which game directory is this for?")
		# Not in the basic game shit, check for support in default
		if gamedir is not None and gamedir not in kv.keys():
			default = kv.get("#default")
			# There's a default entry, check for supported
			if default:
				supported = kv.get("#supported")
				if supported:
					if gamedir in supported.values():
						return gamedir
					return ""
				return "#default"
			return ""
	else:
		# 1 item, see if it's a default
		gamedir = list(kv.keys())[0]
		if gamedir == "#default":
			default = kv.items()[0]
			# If it has multiple supports, check and see if we're in there
			supported = kv.get("#supported")
			if supported:
				if len(supported.items()) > 1:
					gamedir = idaapi.ask_str("", 0, "There are multiple games supported by this file. Which game directory is this for?")
					if gamedir is not None and gamedir in default["#supported"].values():
						return gamedir
					return ""
				return list(supported.values())[0]
			return "#default"

	return gamedir

def get_voffs(name):
	os = get_os()
	if os == OS_Linux:
		mangled = "_ZTV{}{}".format(len(name), name)
		offset = 8
	else:
		mangled = "??_7{}@@6B@".format(name)
		offset = 0

	addr = idc.get_name_ea_simple(mangled)
	if addr != idc.BADADDR:
		addr += offset
	return addr

def read_vtable(funcname, ea):
	funcs = {}
	offset = 0
	while ea != idc.BADADDR:
		if idaapi.inf_is_64bit():
			offs = idaapi.get_qword(ea)
		else:
			offs = idaapi.get_dword(ea)

		if not idaapi.is_code(idaapi.get_full_flags(offs)):
			break

		name = idc.get_name(offs, idaapi.GN_VISIBLE)
		demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
		if demangled == None:
			demangled = name

		if "(" in demangled:
			demangled = demangled[:demangled.find("(")]
		funcs[demangled.lower()] = offset

		offset += 1
		ea = idaapi.next_head(ea, idc.BADADDR)

	# We've got a list of function names, let's do this really shittily because idk any other way

	# This is a good programmer who makes their gamedata the proper way :)
	offs = funcs.get(funcname.lower(), -1)
	if offs != -1:
		return offs

	# Often done but sometimes there are subclass types thrown in, save those too
	if "::" in funcname:
		funcname = funcname[funcname.find("::")+2:]

	# Try by exact function name
	funcnames = {}
	for key, value in get_bcompat_items(funcs):
		# Function overloads can fuck right off
		s = key[key.find("::")+2:].lower() if "::" in key else key.lower()
		funcnames[s.lower()] = value

	offs = funcnames.get(funcname.lower(), -1)
	# Second best way, exact function name
	if offs != -1:
		return offs

	return -1
	# Anything else near here is either some random mem offset or some other crap
#	possibilities = [key for key in funcnames.keys() if funcname in key]
#	return [found for found in funcnames[x] for x in possibilities]

# So we've a few options with finding appropriate vtable offsets
# Option 1: Check and see if they use the optimal naming sequence "Type::Function" and revel in that
# If we can't deduce that exactly, try option 2
# Option 2: They must've used just the function name, run through every function that has a name like that
# and perform option 1 on each
# Windows can suck a wiener on this one
def try_get_voffset(funcname):
	if "(" in funcname:
		funcname = funcname[:funcname.find("(")]
	if "::" in funcname:
		# Option 1
		typename = funcname[:funcname.find("::")]
		voffs = get_voffs(typename)
		offs = -1
		if voffs != idc.BADADDR:
			offs = read_vtable(funcname, voffs)
		if offs != -1:
			return offs

		funcname = funcname[funcname.find("::")+2:]

	# Let's chug along all of these functions, woohoo for option 2!
	for func in idautils.Functions():
		name = idc.get_name(func, idaapi.GN_VISIBLE)
		if not name or funcname not in name:	# funcname should only be a plain function decl, so it would be unfettered in a mangled name
			continue

		demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
		if demangled == None:
			continue

		demname = demangled
		if "::" in demname:
			demname = demname[demname.find("::")+2:]
		if "(" in demname:
			demname = demname[:demname.find("(")]

		if funcname == demname:		# Here's an exact match, let's get the type name then read the vtable
			if "::" not in demangled:	# Okay, so someone somewhere is an idiot and managed to provide an offset name that is the
				continue				# same name as some non-class function and this will manage to catch that

			typename = demangled[:demangled.find("::")]
			voffs = get_voffs(typename)
			if voffs != idc.BADADDR:
				offs = read_vtable(funcname, voffs)
				if offs != -1:
					return offs

	return -1	# Your naming conventions suck and you should feel bad. Or this is Windows and you should still feel bad

def main():
	kv = None
	filereq = idaapi.ask_file(0, "*.txt", "Select a gamedata file")
	if filereq is  None:
		return

	# Try and capture the huge exception that happens if there are multi-line comments
	# Why does vdfparse print the entire file? Lol
	try:
		with open(filereq) as f:
			kv = vdf.load(f)
	except Exception as e:
		idaapi.warning("Could not load file!\nSee console for details")
		import traceback
		traceback.print_exc(type(e), e, e.__traceback__)
		if "vdf.parse: unexpected EOF" in str(e):
			print("[Gamedata Checker] This is likely due to multi-line comments in the gamedata file. Try removing them and try again")
		return

	if kv == None:
		idaapi.warning("Could not load file!")
		return

	kv = list(kv.values())[0]
	os = get_os()
	gamedir = get_gamedir(kv)
	if not gamedir:
		idaapi.warning("Could not find game directory in file")
		return

	kv = kv[gamedir]
	found = {
		"Signatures": {},
		"Offsets": {}
	}

	signatures = kv.get("Signatures")
	if signatures:
		for name, handle in signatures.items():
			s = handle.get(osstr(os))
			if s:
				found["Signatures"][name] = checksig(s)

	offsets = kv.get("Offsets")
	if offsets:# and os != "windows":
		for name, handle in offsets.items():
			offset = handle.get(osstr(os), -1)
			if offset != -1:
				found["Offsets"][name] = [offset, try_get_voffset(name)]

	checkmark = u"\u2713".encode("utf8") if version_info[0] <= 2 else "✓"

	# Format the output string so it's pretty
	try:
		maxlen = max([len(key) for key in found["Signatures"].keys()])
	except:
		maxlen = 0
	if maxlen:
		# Align maxlen to 4
		if maxlen % 4 != 0:
			maxlen += 4 - (maxlen % 4)

		print("Signatures:")
		for key, value in get_bcompat_items(found["Signatures"]):
			print(f"\t{key:{maxlen}}{checkmark if value else 'INVALID'}")

	try:
		maxlen = max([len(key) for key in found["Offsets"].keys()])
	except:
		maxlen = 0
	if maxlen:
		# Align maxlen to 4
		if maxlen % 4 != 0:
			maxlen += 4 - (maxlen % 4)

		# Trial and error and trial and error and trial and
		print(f"Offsets:{'Gamedata':>{maxlen + 9}}{'Current':>12}{'Status':>12}")
		for key, value in get_bcompat_items(found["Offsets"]):
			s = f"\t{key:{maxlen}}"
			foundval = value[1]
			status = checkmark
			if isinstance(value[1], list):
				status = checkmark if value[0] in value[1] else 'X'
			elif int(value[0]) != int(value[1]):
				status = 'X'
				if value[1] == -1:
					foundval = "N/A"
			
			s += f"{value[0]:<12} {foundval:<12} {status:<12}"

			print(s)

main()