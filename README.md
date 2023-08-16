# IDA Scripts
Some random IDA scripts I wrote

## V2.0

These scripts were heavily modified on 8/16/2023. For a full writeup on the new changes, see [here](https://github.com/Scags/IDA-Scripts/pull/2).

### distfromfunc.py ###

Get the offset from the cursor address and the start of a function. Useful for byte patching.

### gamedata_checker.py ###

Name says it all, but this verifies SourceMod gamedata files. This requires Valve's VDF library, install it with `pip install vdf`.

Has a few quirks with it at the moment:
- It does not support multi-line comments within gamedata files nor will it support multiple instances of `#default` keys. Parsing core SourceMod gamedata files is essentially verboten.
- VTable functions that are stripped cannot be verified, obviously.
- Function overloads tends to mess up VTable offset checking; e.g. `GiveNamedItem`.
- Offset checking is variably difficult depending on naming conventions. If the gamedata key name is not named exactly the same as the function name, it will not be found; e.g. `OnTakeDamage` -> `CBaseEntity::OnTakeDamage` and `CTFPlayer::OnTakeDamage` -> `CBaseEntity::OnTakeDamage` but `TakeDamage` != `CBaseEntity::OnTakeDamage`.


### isgoodsig.py ###

Takes a SourceMod (or any) signature input and detects if it's unique or not.


### makesig.py ###

Python translation of [makesig](https://github.com/alliedmodders/sourcemod/blob/master/tools/ida_scripts/makesig.idc).

Optionally, install pyperclip with `pip install pyperclip` to automatically copy any signatures to your clipboard when running.


### makesigfromhere.py ###

Creates a signature from the cursor offset. Useful for byte patching.


### nameresetter.py ###

Resets the name of every function in IDA's database. Does not include library or external functions.


### netprop_importer.py ###

Imports netprops and owner classes as structs and struct members into IDA's DB. Only works with the XML file provided by sm_dump_netprops_xml. Datatables only work most of the time. You should also use the proper netprop dump for your OS, or else you will be very confused.


### sigfind.py ###

Takes a SourceMod (or any) signature and jumps you to the function it's for. If it's a bad signature, then you won't go anywhere.


### sigsmasher.py ###

Makes SourceMod ready signatures for every function in IDA's database. Yes, this will take a long, long time. Requires PyYAML so you'll need to `pip install pyyaml`. You have the option of only generating signatures for typed functions so this works very well with the Symbol Smasher.


### structfiller.py ###

Sanitizes undefined struct members as if IDA had parsed a header file. Each structure will have its undefined members replaced with a one-byte-sized member in order to prevent pseudocode from falling apart. Only makes sense to use it after running the netprop importer.


### symbolsmasher.py ###

Renames functions in a stripped library database based on unique string cross-references.

Running the script presents 2 options: you can read and export data from the current database, or you can import and write data into it.

If you're on a symbol library, you should run it in read mode and export it to a file. This file is what is used to import back into a stripped binary.

When on Windows or another stripped database, run the script in write mode and select the file you exported earlier. A solid amount of functions should be typed within a few seconds.

This works well with the Signature Smasher. However to save you an hour or so, I publicly host dumps of most Source games [here](http://scag.site.nfoservers.com/sigdump).

### vtable_io.py ###

Imports and exports virtual tables. Run it through a Linux binary to export to a file, then run it through a Windows binary to import those VTables into the database. This is similar to [Asherkin's VTable Dumper](https://asherkin.github.io/vtable/) but doesn't suffer from the pitfalls of multiple inheritance. Since it doesn't have those liabilities, its function typing will almost always be perfect.

#### Features ####
This script is slightly heavy and has features that warrant explanation. Features can be freely enabled/disabled in the popup form that opens when you run the script. Desired features options are kept in the IDA registry and will persist.

**Parse type strings**
- Sometimes IDA fails to properly analyze Windows RTTI Type Descriptor objects. Because of this, there won't be a reference from certain type descriptors to std::type_info, which is required for the script to work.
- If this feature is enabled, then the string names of the type descriptor will be parsed in order to discover the unreferencing type descriptors. This will be done alongside the normal script function.
- If you notice that there are multiple functions of the same name or classes that have virtual functions that aren't typed, consider enabling this.
- It should be harmless to keep on regardless, but it is disabled by default.
- This problem only seemed to be present in NMRiH.

**Skip vtable size mismatches**
- The script is *almost* perfect. On rare occasion, it will fail to properly prepare a Windows translation of a Linux virtual table.
- If this option is enabled, then any size mismatches will forego function typing.
- Enabled by default.

**Comment reused functions**
- Windows oftentimes optimizes shorter and simpler functions and reuses them across multiple virtual tables. This means that it would be redundant to rename these functions over and over again.
- If enabled, virtual table declarations instead emplace a comment on the function's reference.
- Enabled by default.

**Export options**
- Should be self-explanatory, but the script is able to export the Linux and Windows virtual tables to a file.
- This is is a .json file and is organized to be readable.
- The format of the export file is as follows:
```json
"classname"
{
	"[this-offset]	vtable-offset	function-name"
}
```
- Linux offsets are denoted with `L` and Windows with `W`. If the function is not present in a certain OS, then that index is empty.
- Exporting is optional, and if it is not enabled, then the export file path option can be safely ignored.

### vtable_structs.py ###

Runs through virtual tables and creates structs for them. Doesn't work with template classes. Use at your own risk since it screws up refencing members through pseudocode.