'''
Lexmark's Pagemaker has what appears to be a symbol table for Postscript (and other) handlers.
.rodata:00378A1C sym_table       postscript_handler <aAbs, sub_103A10, 0, 0>
.rodata:00378A1C                                         ; DATA XREF: sub_6690C+48↑o
.rodata:00378A1C                                         ; sub_66BA4+8↑o ...
.rodata:00378A1C                 postscript_handler <aAdd_0, sub_1033A8, 0, 1> ; "PPDS" ...
.rodata:00378A1C                 postscript_handler <aAload, sub_105048, 0, 2>
.rodata:00378A1C                 postscript_handler <aAnchorsearch, sub_AA508, 0, 3>
.rodata:00378A1C                 postscript_handler <aPInfoDevinfoFl+0x20, sub_7FAE8, 0, 4>
.rodata:00378A1C                 postscript_handler <aBgcArc+4, sub_D6550, 0, 5>
.rodata:00378A1C                 postscript_handler <aArcn, sub_D696C, 0, 6>
.rodata:00378A1C                 postscript_handler <aArct, sub_D9B20, 0, 7>
.rodata:00378A1C                 postscript_handler <aArcto, sub_D9B18, 0, 8>
.rodata:00378A1C                 postscript_handler <aArray, sub_1044AC, 0, 9>
.rodata:00378A1C                 postscript_handler <aAshow, sub_13E5B8, 0, 0xA>
.rodata:00378A1C                 postscript_handler <aAstore, sub_1051E0, 0, 0xB>
.rodata:00378A1C                 postscript_handler <aAwidthshow, sub_13EB20, 0, 0xC>
.rodata:00378A1C                 postscript_handler <aMarkFontsetini+0x28, sub_A7E18, 0, 0xD>
.rodata:00378A1C                 postscript_handler <aBind, sub_80E20, 0, 0xE>
.rodata:00378A1C                 postscript_handler <aBitshift, sub_7FD3C, 0, 0xF>
.rodata:00378A1C                 postscript_handler <aCeiling, sub_103B08, 0, 0x10>
.rodata:00378A1C                 postscript_handler <aCharpath, sub_13F7C0, 0, 0x11>
.rodata:00378A1C                 postscript_handler <aClear_0, sub_1031C8, 0, 0x12>
.rodata:00378A1C                 postscript_handler <aMarkExchSetcol+0x18, sub_1032B8, 0, 0x13>
.rodata:00378A1C                 postscript_handler <aRectclip+4, sub_D81A8, 0, 0x14>
.rodata:00378A1C                 postscript_handler <aViewclippath+4, sub_D7554, 0, 0x15>
.rodata:00378A1C                 postscript_handler <aClosepath_0, sub_D728C, 0, 0x16>

There are over 1000 of these structure definitions. This script auto-renames (and defines) the functions.
'''

from idautils import *
from idc import *
from idaapi import *

struct_size = 0x10
struct_objs = 1302
start = get_name_ea_simple("sym_table") # must be defined! Lives at 0x00378A1C in Pagemaker
end = start+(struct_size*struct_objs)

print("Iterating from 0x%08x to 0x%08x" % (start, end))
while start < end:
    proposed_func_name = idc.Dword(start)
    func_addr = idc.Dword(start+4)
    fname = GetFunctionName(func_addr)
    if(func_addr == idc.BADADDR or fname == ""):
        print("Skipping @ 0x%08X" % start)
        start += struct_size
        continue;       

    proposed_name = str(get_strlit_contents(proposed_func_name, -1, ida_nalt.STRTYPE_C))
    print("Offset: %08x" % start)
    print("Current name: %s" % fname)
    print("Proposed name: %s" % proposed_name)
    print("Address: 0x%08x" % func_addr)
    print("")

    MakeFunction(func_addr)
    idaapi.set_name(func_addr, proposed_name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK | idaapi.SN_FORCE)

    start += struct_size

print("Done!")
