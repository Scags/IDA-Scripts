import idautils
import idaapi
import idc
import vdf

def get_os():
	# Lazy af lol
	return "linux" if ida_nalt.get_root_filename().endswith(".so") else "windows"

def checksig(sig):
	if sig[0] == '@':
		# Just check for existence of this mangled name
		return idc.get_name_ea_simple(sig[1:]) != idc.BADADDR

	sig = sig.replace(r"\x", " ").replace("2A", "?").replace("2a", "?").replace("\\", "").strip()
	count = 0
	addr = 0
	addr = idc.find_binary(addr, idc.SEARCH_DOWN|idc.SEARCH_NEXT, sig)
	while addr != idc.BADADDR:
		count = count + 1
		addr = idc.find_binary(addr, idc.SEARCH_DOWN|idc.SEARCH_NEXT, sig)

	return count == 1

# Unfortunately I don't care too much about overtly complex gamedata files
# If you have multiple #default's in you first subsection or you have #default
# anywhere else other than that first subsection, you're SOL. Sorry Silvers :c
def get_gamedir(kv):
	gamedir = ""
	# If we've got multiple games supported, so let's just ask
	if len(kv.items()) > 1:
		gamedir = ida_kernwin.ask_str("", 0, "There are multiple supported games with this file. Which game directory is this for?")
		# Not in the basic game shit, check for support in default
		if gamedir not in kv.keys():
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
		gamedir = kv.keys()[0]
		if gamedir == "#default":
			default = kv.items()[0]
			# If it has multiple supports, check and see if we're in there
			supported = kv.get("#supported")
			if supported:
				if len(supported.items()) > 1:
					gamedir = ida_kernwin.ask_str("", 0, "There are multiple supported games with this file. Which game directory is this for?")
					if gamedir in default["#supported"].values():
						return gamedir
					return ""
				return supported.values()[0]
			return "#default"

	return gamedir

def get_thisoffs(name):
	mangled = "_ZTV{}{}".format(len(name), name)
	return idc.get_name_ea_simple(mangled)

def read_vtable(funcname, ea):
	funcs = {}
	offset = 0
	while ea != idc.BADADDR:
		offs = idc.get_wide_dword(ea)
		if not ida_bytes.is_code(ida_bytes.get_full_flags(offs)):
			break

		name = idc.get_name(offs, ida_name.GN_VISIBLE)
		demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
		if demangled == None:
			demangled = name

		if "(" in demangled:
			demangled = demangled[:demangled.find("(")]
		funcs[demangled.lower()] = offset

		offset += 1
		ea = ida_bytes.next_not_tail(ea)

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
	for key, value in funcs.iteritems():
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
		thisoffs = get_thisoffs(typename)
		offs = -1
		if thisoffs != idc.BADADDR:
			offs = read_vtable(funcname, thisoffs + 8)
		if offs != -1:
			return offs

		funcname = funcname[funcname.find("::")+2:]

	# Let's chug along all of these functions, woohoo for option 2!
	for func in idautils.Functions():
		name = idc.get_name(func, ida_name.GN_VISIBLE)
		if funcname not in name:	# funcname should only be a plain function decl, so it would be unfettered in a mangled name
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
			thisoffs = get_thisoffs(typename)
			if thisoffs != idc.BADADDR:
				offs = read_vtable(funcname, thisoffs + 8)
				if offs != -1:
					return offs

	return -1	# Your naming conventions suck and you should feel bad. Or this is Windows and you should still feel bad

def main():
	kv = None
	with open(ida_kernwin.ask_file(0, "*.txt", "Select a gamedata file")) as f:
		kv = vdf.load(f)

	if kv == None:
		ida_kernwin.warning("Could not load file!")
		return

	kv = kv.values()[0]
	os = get_os()
	gamedir = get_gamedir(kv)
	if not gamedir:
		ida_kernwin.warning("Could not find game directory in file")
		return

	kv = kv[gamedir]
	found = {
		"Signatures": {},
		"Offsets": {}
	}

	signatures = kv.get("Signatures")
	if signatures:
		for name, handle in signatures.items():
			s = handle.get(os)
			if s:
				found["Signatures"][name] = checksig(s)

	offsets = kv.get("Offsets")
	if offsets and os != "windows":
		for name, handle in offsets.items():
			offset = handle.get(os, -1)
			if offset != -1:
				found["Offsets"][name] = [offset, try_get_voffset(name)]

	if len(found["Signatures"].items()):
		print("Signatures:")
		for key, value in found["Signatures"].iteritems():
			print("\t{} - {}".format(key, u"\u2713".encode("utf8") if value else "INVALID"))

	if len(found["Offsets"].items()):
		print("Offsets:")
		for key, value in found["Offsets"].iteritems():
			s = "\t{} - ".format(key)
			if isinstance(value[1], list):
				s += "{} == {} - {}".format(value[0], value[1], u"\u2713".encode("utf8") if value[0] in value[1] else "INVALID")
			else:
				if int(value[0]) == int(value[1]):
					s += "{} == {} - {}".format(value[0], value[1], u"\u2713".encode("utf8"))
				else:
					s += "{} == {} - {}".format(value[0], value[1], "NOT FOUND" if value[1] == -1 else "INVALID")

			print(s)

	if os == "windows" and kv.get("Offsets"):
		print("Offset checking is not supported on Windows binaries")

	ida_kernwin.warning("Check console for output")

if __name__ == "__main__":
	main()