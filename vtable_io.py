import idc
import idautils
import idaapi
#import yaml
import json 	# YAML is just too slow for this

from sys import version_info

OS_Linux = 0
OS_Win = 1

FUNCS = 0

# Change to 0 to disable weak typing. This will speed up the script but you'll have a lot of shitty repeat names
USE_WEAK_NAMES = True

def get_os():
	global OS_Win, OS_Linux
	# Lazy af lol
	return OS_Linux if ida_nalt.get_root_filename().endswith(".so") else OS_Win

def get_bcompat_keys(d):
	return d.keys() if version_info[0] >= 3 else d.iterkeys()

def get_bcompat_items(d):
	return d.items() if version_info[0] >= 3 else d.iteritems()

def mangle_vtablename(name):
	global OS_Linux

	if get_os() == OS_Linux:
		mangledname = "_ZTV{}{}".format(len(name), name)
	else:
		mangledname = "??_7{}@@6B@".format(name)

	return mangledname

# Does not work for complex types (templates, inner classes, etc)
def get_vtable(name):
	return idc.get_name_ea_simple(mangle_vtablename(name))

def parse_vtable(ea, typename):
	global OS_Linux, OS_Win
	os = get_os()
	if os == OS_Linux:
		ea += 8
	funcs = []

	while ea != idc.BADADDR:
		offs = idc.get_wide_dword(ea)
		if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
			if ida_bytes.is_unknown(ida_bytes.get_full_flags(ea)):
				break

			size = idc.get_item_size(ea)	# This is bad abd abadbadbadbabdbabdad but there's no other choice here
			if size != 4:
				break

		name = idc.get_name(offs, ida_name.GN_VISIBLE)
		if name:
			if os == OS_Linux:
				if not(name.startswith("_Z") or name.startswith("__cxa")) or name.startswith("_ZTV"):
					break 	# If we've exceeded past this vtable
			elif name.startswith("??"):
#				unmangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
#				if not unmangled or typename not in unmangled:
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
	return funcs

# (funcaddr, funcname)
def get_thunks(ea, typename, funclist):
	funcidx = 0
	for i in range(len(funclist)):
		if isinstance(funclist[i], (int, long)):
			funcidx = i
			break

	# No thunks here
	if not funcidx:
		return [], []

	funcs = []
	gotthunks = False

	# Index all these thunks so they line up for when we check for an offset
	# Get rid of extra destructor too
	thunklist = [get_func_postname(i) for i in funclist[funcidx:] if not isinstance(i, (int, long)) and not i.startswith("_ZTI") and not i.endswith(typename + "D1Ev")]

	while ea != idc.BADADDR:
		offs = idc.get_wide_dword(ea)
		size = idc.get_item_size(ea)
		if size != 4:
			break

		name = idc.get_name(offs, ida_name.GN_VISIBLE)
		if name:
			if name.startswith("??"):
				if typename not in name:
					break

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
	found = set()
	while ea < end and ea != idc.BADADDR:
		dword = ida_bytes.get_wide_dword(ea)
		name = idc.get_name(dword, ida_name.GN_VISIBLE)

		if name and name.startswith("_ZTI") and not name in found:
			demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
			if not demangled:
				ea = ida_bytes.next_head(ea, end)
				continue

			found.add(name)
			actualname = demangled.split("'")[1]
			vtable = get_vtable(actualname)
			if vtable == idc.BADADDR:
				ea = ida_bytes.next_head(ea, end)
				continue

			node = parse_vtable(vtable, actualname)
			if len(node):
				root[actualname] = node

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

	if unmangled.find("::") != -1:
		unmangled = unmangled[unmangled.find("::")+2:]

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
	global FUNCS, USE_WEAK_NAMES, BAD
	# Compat for 2.7, strings are in unicode
	funclist = [i if isinstance(i, (int, long)) else i.encode("ascii") for i in linuxtable[key]]
	thunks, thunklist = get_thunks(winv, key, funclist)

	# We've got the thunks, now we don't need anything beyond another typeinfo
	for i, v in enumerate(funclist):
		if isinstance(v, (int, long)):
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

		shortname = get_func_postname(n)
		if not shortname:
			i += 1
			continue

		# Windows skips the vtable function if it exists in the thunks and 
		# the thunk does not jmp into it (because the thunk is the function)
		try:
			if i < len(wintable):
				thunkidx = thunklist.index(shortname)
				if not isinthunk(wintable[i], thunks[thunkidx]):
					currname = idc.get_name(thunks[thunkidx][0], ida_name.GN_VISIBLE)

					if currname and currname != funclist[i]:
						nameflags = ida_name.SN_FORCE
						if not currname.startswith("sub_"):
							if not USE_WEAK_NAMES:
								del funclist[i]
								continue

							nameflags |= ida_name.SN_WEAK
						elif USE_WEAK_NAMES:
							FUNCS += 1

						idc.set_name(thunks[thunkidx][0], funclist[i], nameflags)

					del funclist[i]
					continue
			else:	# Class has thunks at the end of the vtable
					# This doesn't change anything but it should link up the lengths of both tables
				del funclist[i]
				continue
		except:
			pass

		node = funcoverloads.get(shortname, [])

		# Is this a half-ass decent overload
		go = 0
		for loadnode in range(len(node)):
			if not any([i - funclist.index(val) > FUCK for val in node[loadnode]]):
				node[loadnode].append(n)
				go = 1
				break
		if go:
			node.append([n])

		funcoverloads[shortname] = node
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
	# OK THIS IS REALLY REALLY BAD BUT SOMETIMES OVERLOADS GET DUPED AND IDK WHY
#	return [val for n, val in enumerate(funclist) if val not in funclist[:n] or val.startswith("__cxa")]

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
		elif USE_WEAK_NAMES:
			FUNCS += 1

		idc.set_name(dword, functable[i], nameflags)
		i += 1
		ea = ida_bytes.next_not_tail(ea)

def parse_from_key(linuxtable, key):
	winv = get_vtable(key)
	if winv == idc.BADADDR:
		return

	wintable = parse_vtable(winv, key)
	if not len(wintable):
		return

	funclist = prep_vtable(linuxtable, key, wintable, winv)
	write_vtable(winv, funclist, key)

def write_vtables():
	f = ida_kernwin.ask_file(0, "*.json", "Select a file to import from")
	if not f:
		return

	linuxtable = None
	ida_kernwin.replace_wait_box("Importing file")
	with open(f) as f:
		linuxtable = json.load(f)

	ida_kernwin.replace_wait_box("Comparing vtables")
	for key in get_bcompat_keys(linuxtable):
		parse_from_key(linuxtable, key)

def main():
	global OS_Linux
	os = get_os()

	if os == OS_Linux:
		read_vtables()
	else:
		write_vtables()
		global FUNCS
		if FUNCS:
			print("Successfully typed {} virtual functions".format(FUNCS))

if __name__ == "__main__":
	main()