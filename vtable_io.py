import idc
import idautils
import idaapi
#import yaml
import json 	# YAML is just too slow for this

from sys import version_info

OS_Linux = 0
OS_Win = 1

FUNCS = 0

# For exporting successful table builds
EXPORT = 0
EXPORT_TABLE = {}

Export_No = -1
Export_YesOnly = 0
Export_Yes = 1

# Change to 0 to disable weak typing. This will speed up the script but you'll have a lot of shitty repeat names
USE_WEAK_NAMES = 0

def get_os():
	# Lazy af lol
	return OS_Linux if ida_nalt.get_root_filename().endswith(".so") else OS_Win

def get_bcompat_keys(d):
	return d.keys() if version_info[0] >= 3 else d.iterkeys()

def get_bcompat_items(d):
	return d.items() if version_info[0] >= 3 else d.iteritems()

def parse_vtable(ea, typename):
	os = get_os()
	if os == OS_Linux:
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

			s = "".join(["%02x" % idc.get_wide_byte(ea + i) for i in range(3, -1, -1)])#.replace("0x", "")
			if not s.lower().startswith("ffff"):
				ea = ida_bytes.next_not_tail(ea)
				continue

			offs = int(s, 16)
			ea += 3

		name = idc.get_name(offs, ida_name.GN_VISIBLE)
		if name:
			if os == OS_Linux:
				if not(name.startswith("_Z") or name.startswith("__cxa")) or name.startswith("_ZTV"):
					break 	# If we've exceeded past this vtable
			elif name.startswith("??"):
				break
		else:
			if os == OS_Win:
				break

			# dd -offsettothis
			# This is even worseworsoewewrosorooese
			s = "%02x" % offs
			if not s.lower().startswith("ffff"):
				ea = ida_bytes.next_not_tail(ea)
				continue

			name = (1 << 32) - int(offs)
		funcs.append(name)

		ea = ida_bytes.next_not_tail(ea)
	return funcs, eatemp

# (funcaddr, funcname)
def get_thunks(ea, typename, funclist):
	funcidx = 0
	for i in range(len(funclist)):
		if version_info[0] < 3:
			if isinstance(funclist[i], (int, long)):
				funcidx = i
				break
		else:
			if isinstance(funclist[i], int):
				funcidx = i
				break

	# No thunks here
	if not funcidx:
		return [], []

	funcs = []
	gotthunks = False

	# Index all these thunks so they line up for when we check for an offset
	# Get rid of extra destructor too
	instance = (int, long) if version_info[0] < 3 else int
	thunklist = [get_func_postname(i) for i in funclist[funcidx:] if not isinstance(i, instance) and not i.startswith("_ZTI") and not i.endswith(typename + "D1Ev")]

	while ea != idc.BADADDR:
		size = idc.get_item_size(ea)

		# CTFRocketLauncher_DirectHit has its thunks below some random ass string
		# Don't know what's up with that but we'll check 2 more offsets beyond that
		if size != 4:
			ea = ida_bytes.next_not_tail(ea)
			size = idc.get_item_size(ea)
			if size != 4:
				ea = ida_bytes.next_not_tail(ea)
				size = idc.get_item_size(ea)
				if size != 4:	# This is really bad
					break

		offs = idc.get_wide_dword(ea)
		name = idc.get_name(offs, ida_name.GN_VISIBLE)

		if name:
			if name.startswith("??_R4"):
#				if typename not in name:
#					break

				gotthunks = True
				ea = ida_bytes.next_not_tail(ea)
				continue
		else:
			s = "%02x" % offs
			if not s.lower().startswith("ffff"):
				ea = ida_bytes.next_not_tail(ea)
				continue

			break

		if gotthunks:
			funcs.append((offs, name))

		ea = ida_bytes.next_not_tail(ea)

	return funcs, thunklist

def read_vtables():
	f = ida_kernwin.ask_file(1, "*.json", "Select a file to export to")
	if not f:
		return

	seg = ida_segment.get_segm_by_name(".rodata")
	ea = seg.start_ea
	end = seg.end_ea

	ida_kernwin.replace_wait_box("Reading vtables")
	root = {}
	while ea < end and ea != idc.BADADDR:
		dword = ida_bytes.get_wide_dword(ea)
		name = idc.get_name(dword, ida_name.GN_VISIBLE)

		if name and name.startswith("_ZTI"):
			demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
			if not demangled:
				ea = ida_bytes.next_head(ea, end)
				continue

			if ida_bytes.get_item_size(ea - 4) == 4 and ida_bytes.get_wide_dword(ea - 4) == 0:
				actualname = demangled.split("'")[1]

				node, ea = parse_vtable(ea - 4, actualname)
				if len(node):
					root[actualname] = node

				continue

		ea = ida_bytes.next_head(ea, end)

	ida_kernwin.replace_wait_box("Exporting to file")
	with open(f, "w") as f:
		json.dump(root, f, indent = 4, sort_keys = True)

# Function name only, no params or classname
def get_func_sname(name):
	unmangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
	if unmangled is None:
		return ""

	if unmangled.find("::") != -1:
		unmangled = unmangled[unmangled.find("::")+2:]
	if unmangled.find("(") != -1:
		unmangled = unmangled.split("(")[0]
	return unmangled

# Classname
def get_func_tname(name):
	unmangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
	if unmangled is None:
		return ""

	if unmangled.find("::") != -1:
		unmangled = unmangled[:unmangled.find("::")]

	return unmangled

#()
def get_func_argnames(name):
	unmangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
	if unmangled is None:
		return ""

	if unmangled.find("(") != -1:
		unmangled = unmangled[unmangled.find("("):]

	return unmangled

# Anything past Classname::
# Thank you CTFPlayer::SOCacheUnsubscribed...
def get_func_postname(name):
	unmangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
	if unmangled is None:
		return ""

	if unmangled[:unmangled.find("(")].rfind("::") != -1:
		unmangled = unmangled[unmangled[:unmangled.find("(")].rfind("::")+2:]

	return unmangled

def isinthunk(winname, thunk):
	ea, name = thunk
	funcstart = idc.get_func_attr(ea, idc.FUNCATTR_START)
	funcend = idc.get_func_attr(ea, idc.FUNCATTR_END)

	if funcend - funcstart > 20:	# Highest I've seen is 13 opcodes but this works ig
		return False

	addr = idc.next_head(funcstart, funcend)

	if addr == idc.BADADDR:
		return False

	b = idc.get_wide_byte(addr)
	if b in (0xEB, 0xE9):
		dis = idc.generate_disasm_line(addr, 0)
 		try:
	 		funcname = dis[dis.find("jmp")+3:].strip()
	 		if funcname.find("short") != -1:
	 			funcname = funcname[funcname.find("short")+5:].strip()

	 		# When this function gets typed, a comment is added
	 		# Remove it
	 		if funcname.find(";") != -1:
	 			funcname = funcname[:funcname.find(";")]

	 		if funcname == winname:
	 			return True
	 	except:
	 		pass

	return False

# I GIVE UP
# I don't know if it's possible, but of the 3 quintillion hurdles I've had to 
# jump through to make this script work, the most frustrating was subclass overloads
# Let's say we have A::Foo(int) and subclass B::Foo(void)
# The script says "hey these are subclasses so let's not add them together"
# That works iff B does not override Foo(int)
# SO LET'S SAY WE ARE NextBotCombatCharacter AND WE WOULD LIKE TO OVERRIDE CBaseAnimating::Ignite
# THAT'S COOL, NOW LET'S ALSO OVERLOAD THAT FUNCTION WITH NextBotCombatCharacter::Ignite(float, CBaseEntity*)
# FUCK
# So to counter that, I have officially given up and have decided to check for an arbitrary offset
# If the offset between overload A and overload B is greater than FUCK, we give up
# Change at your own demise
FUCK = 30

def prep_vtable(linuxtable, key, wintable, winv):
	if not linuxtable.get(key):
		return None

	# Compat for 2.7, strings are in unicode
	if version_info[0] < 3:
		funclist = [i if isinstance(i, (int, long)) else str(i) for i in linuxtable[key]]
	thunks, thunklist = get_thunks(winv, key, funclist)

	# We've got the thunks, now we don't need anything beyond another typeinfo
	for i, v in enumerate(funclist):
		if version_info[0] < 3:
			if isinstance(v, (int, long)):
				funclist = funclist[:i]		# Skipping thisoffs
				break
		else:
			if isinstance(v, int):
				funclist = funclist[:i]		# Skipping thisoffs
				break

	# Get rid of extra destructor for linux
	for i, n in enumerate(funclist):
		name = idc.demangle_name(n, idc.get_inf_attr(idc.INF_SHORT_DN))
		if name:
			if "::~" in name:
				del funclist[i]
				break

	# Windows does overloads backwards, reverse them
	# Also check for thunks while we're at it
	i = 0
	funcoverloads = {}
	while i < len(funclist):# and i < len(wintable):
		n = funclist[i]
		if n.startswith("__cxa"):
			i += 1
			continue

		# I shouldn't need to do this, but destructors are wonky
		if i == 0:
			demangled = idc.demangle_name(n, idc.get_inf_attr(idc.INF_SHORT_DN))
			if demangled and "::~" in demangled:
				i += 1
				continue

		overloadname = get_func_sname(n)
		shortname = get_func_postname(n)
		if not shortname:
			i += 1
			continue

		# Windows skips the vtable function if it exists in the thunks and 
		# the thunk does not jmp into it (because the thunk is the function)
		try:
			thunkidx = thunklist.index(shortname)
			delete = 1
		except:
			thunkidx = -1
			delete = 0
		if i < len(wintable):
			if thunkidx != -1 and thunkidx < len(thunks):
				if not isinthunk(wintable[i], thunks[thunkidx]):
					currname = idc.get_name(thunks[thunkidx][0], ida_name.GN_VISIBLE)

					if currname and currname != funclist[i] and EXPORT_MODE != Export_YesOnly:
						nameflags = ida_name.SN_FORCE
						if not currname.startswith("sub_"):
							if not USE_WEAK_NAMES:
								del funclist[i]
								continue

							nameflags |= ida_name.SN_WEAK
						elif USE_WEAK_NAMES:
							global FUNCS
							FUNCS += 1

						idc.set_name(thunks[thunkidx][0], funclist[i], nameflags)

					del funclist[i]
					continue
		else:	# Class has thunks at the end of the vtable
				# This doesn't change anything but it should link up the lengths of both tables
			if delete:
				del funclist[i]
				continue

		node = funcoverloads.get(overloadname, [])

		# Is this a half-ass decent overload
		go = 1
		for loadnode in range(len(node)):
			if not any([i - funclist.index(val) > FUCK for val in node[loadnode]]):
				node[loadnode].append(n)
				go = 0
				break

		if go:
			node.append([n])

		funcoverloads[overloadname] = node
		i += 1

	for k, value in get_bcompat_items(funcoverloads):
#		if len(value) <= 1:
#			continue

#		split = []
#
#		# Since subclass overloads shouldn't scoot up next to their baseclass brethren
#		# hackily separate overloads by classname
#		for mname in value:
#			found = 0
#
#			name = idc.demangle_name(mname, idc.get_inf_attr(idc.INF_SHORT_DN))
#			typename = name[:name.find("::")]
#
#			for i2 in range(len(split)):
#				for othermname in split[i2]:
#					name = idc.demangle_name(othermname, idc.get_inf_attr(idc.INF_SHORT_DN))
#					othertypename = name[:name.find("::")]
#
#					if typename == othertypename:
#						found = 1
#						split[i2].append(mname)
#						break
#
#				if found:
#					break
#
#			if not found:
#				split.append([mname])

		for v in value:
			if len(v) <= 1:
				continue

			lowestidx = len(funclist)
			for func in v:
				temp = funclist.index(func)
				if lowestidx > temp:
					lowestidx = temp

			count = 0
			while len(v):
				k = v.pop()
				funclist.insert(lowestidx + count, funclist.pop(funclist.index(k)))
				count += 1

	diff = len(funclist) - len(wintable)
	if diff:
		print("WARNING: {} vtable may be wrong! L{} - W{} = {}".format(key, len(funclist), len(wintable), diff))

	return funclist

def write_vtable(winv, functable, typename):
	global FUNCS
	ea = winv
	i = 0

	while ea != idc.BADADDR and i < len(functable):
		dword = ida_bytes.get_wide_dword(ea)
		name = idc.get_name(dword, ida_name.GN_VISIBLE)

		if functable[i].startswith("__cxa"):
			i += 1
			ea = ida_bytes.next_not_tail(ea)
			continue

		if name == "__purecall":
			i += 1
			ea = ida_bytes.next_not_tail(ea)
			continue

		if not name or name.startswith("??"):
			break

		if functable[i] == name:
			i += 1
			ea = ida_bytes.next_not_tail(ea)
			continue

		nameflags = ida_name.SN_FORCE
		if not name.startswith("sub_"):
			if not USE_WEAK_NAMES:
				i += 1
				ea = ida_bytes.next_not_tail(ea)
				continue

			nameflags |= ida_name.SN_WEAK
		elif not USE_WEAK_NAMES:
			FUNCS += 1

		idc.set_name(dword, functable[i], nameflags)
		i += 1
		ea = ida_bytes.next_not_tail(ea)

def build_export_table(linlist, winlist):
	for i, v in enumerate(linlist):
		if version_info[0] < 3:
			if isinstance(v, (int, long)):
				funclist = funclist[:i]		# Skipping thisoffs
				break
		else:
			if isinstance(v, int):
				funclist = funclist[:i]		# Skipping thisoffs
				break

	listnode = linlist[:]

	for i, v in enumerate(linlist):
		name = str(v)
		if name.startswith("__cxa"):
			listnode[i] = None
			continue

		s = "L{:<6}".format(i)
		try:
			s += " W{}".format(winlist.index(name))
		except:
			pass

		funcname = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
		s = "{:<16} {}".format(s, funcname)
		listnode[i] = s

	return [i for i in listnode if i != None]

def parse_from_key(linuxtable, key, winv):
	wintable, eatemp = parse_vtable(winv, key)
	if not len(wintable):
		return eatemp

	funclist = prep_vtable(linuxtable, key, wintable, winv)
	if not funclist:
		return eatemp

	if EXPORT_MODE in (Export_Yes, Export_YesOnly):
		global EXPORT_TABLE
		EXPORT_TABLE[key] = build_export_table(linuxtable[key], funclist)

	if EXPORT_MODE != Export_YesOnly:
		write_vtable(winv, funclist, key)

	return eatemp

def search_for_vtables(linuxtable):
	seg = ida_segment.get_segm_by_name(".rdata")
	ea = seg.start_ea
	end = seg.end_ea

	found = set()
	while ea < end and ea != idc.BADADDR:
		if ida_bytes.get_item_size(ea) != 4 or ida_bytes.is_unknown(ida_bytes.get_full_flags(ea)):
			ea = ida_bytes.next_head(ea, end)
			continue

		dword = ida_bytes.get_wide_dword(ea)
		name = idc.get_name(dword, ida_name.GN_VISIBLE)

		if name and name.startswith("??_R4"):
			demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
			if not demangled or demangled in found:
				ea = ida_bytes.next_head(ea, end)
				continue

			if ida_bytes.get_item_size(ea + 4) == 4 and ida_bytes.get_wide_dword(ea + 4) != 0:
				disasm = idc.generate_disasm_line(ea + 4, 0)
				if disasm and disasm.strip().startswith("dd offset"):
					actualname = demangled.split("::`RTTI")[0][6:]
					if actualname in found:
						ea = ida_bytes.next_head(ea, end)
						continue

					found.add(actualname)

					ea = parse_from_key(linuxtable, actualname, ea + 4)
					continue

		ea = ida_bytes.next_head(ea, end)

def write_vtables():
	f = ida_kernwin.ask_file(0, "*.json", "Select a file to import from")
	if not f:
		return

	global EXPORT_MODE
	EXPORT_MODE = ida_kernwin.ask_buttons("Yes", "Export only (do not type functions)", "No", -1, "Would you like to export virtual tables to a file?")

	if EXPORT_MODE in (Export_Yes, Export_YesOnly):
		exportfile = ida_kernwin.ask_file(1, "*.json", "Select a file to export virtual tables to")
		if not exportfile:
			return

	linuxtable = None
	ida_kernwin.replace_wait_box("Importing file")
	with open(f) as f:
		linuxtable = json.load(f)

	ida_kernwin.replace_wait_box("Comparing vtables")
	search_for_vtables(linuxtable)
#	for key in get_bcompat_keys(linuxtable):
#		parse_from_key(linuxtable, key)

	if EXPORT_MODE in (Export_Yes, Export_YesOnly):
		with open(exportfile, "w") as f:
			json.dump(EXPORT_TABLE, f, indent = 4, sort_keys = True)

def main():
	os = get_os()

	if os == OS_Linux:
		read_vtables()
	else:
		write_vtables()
		if FUNCS:
			print("Successfully typed {} virtual functions".format(FUNCS))

if __name__ == "__main__":
	main()