# IDA Scripts
 Some random IDA scripts I wrote

### makesig.py ###

Python translation of [makesig](https://github.com/alliedmodders/sourcemod/blob/master/tools/ida_scripts/makesig.idc)


### isgoodsig.py ###

Takes a SourceMod signature input and detects if it's unique or not.


### netprop_importer.py ###

Imports netprops and owner classes as structs and struct members into IDA's DB. Only works with the XML file provided by sm_dump_netprops_xml. It's still a WIP and doesn't catch all of them though; really shits the bed when it comes to datatables. You should also use the proper netprop dump for your OS, or else you will be very confused.