# dirty script to rename Lexmark subroutines based on logging strings
from idc import *
from ida_xref import *
import idautils

# You must have identified the printf function.

def printf_follow(addr):
    instcount = 0
    
    xref_addr = addr
    func = idaapi.get_func(addr)
    addr = func.startEA
    
    print("--- Checking xref 0x%08x" % xref_addr)
    
    # Special edge case handler for Lexmark Hydra
    # The disassembly loads strings then adjusts the offset.
    # This means strings in the disassembler don't match
    # those in the decompiler (they are incorrect).
    #
    # For example...
    # The code contains combinations of:
    # 000462E8: LDR R3, =(aWaitForConfigK - 0x462FC) @ "wait_for_config_key"
    # ...
    # 00046304: ADD R3, R3, #0x14
    # The actual function name is 'load_plugin', not 'wait_for_config_key'
    # Calculated as &aWaitForConfigK + 0x14
    #
    # The below code looks for these patterns and resolves 
    # the strings to the correct, expected values
    # then renames the reviewed function accordingly.
    # Hacky because we rename in this handler 
    if(GetMnem(xref_addr) == "LDR" and "- 0x" in GetOpnd(xref_addr, 1)):
        print("--- Possible false positive @ 0x%08x. Checking." % xref_addr)

        # move forward n instructions
        str_addr = xref_addr
        for x in range(0, 10):
            str_addr = NextHead(str_addr)
            # is this instruction an "add rX, rX, offset"?
            # where rX is the rX from the 'LDR rX' of our xref?
            if(GetMnem(str_addr) == "ADD" and GetOpnd(xref_addr, 0) == GetOpnd(str_addr, 0) and GetOpnd(str_addr, 0) == GetOpnd(str_addr, 1)):
                #print("--- Found candidate str load @ 0x%08X" % str_addr)

                # get address of loaded string 
                # LDR R2, =(aNpapiRead - 0x3FB994) @ "npapi_read"
                # =(aNpapiRead - 0x3FB994) - we want just "aNpapiRead"
                func_str = GetOpnd(xref_addr, 1)[2:]
                func_str = func_str.split(" ", 1)[0] # func_str = aNpapiRead 

                # now add value to it so we get the correct string
                guessed_func_name = get_name_ea_simple(func_str)+GetOperandValue(str_addr, 2)

                print("--- [*] Renaming %s (%x) to %s" % (GetFunctionName(func.startEA), func.startEA, get_strlit_contents(guessed_func_name, -1)))
                idaapi.set_name(func.startEA, str(get_strlit_contents(guessed_func_name, -1)), idaapi.SN_NOWARN | idaapi.SN_NOCHECK | idaapi.SN_FORCE)
                break
        return 0
    elif(GetMnem(xref_addr) == "ADD" or GetMnem(xref_addr) == "SUB"):
        print("--- Definite false positive @ 0x%08x. Skipping." % xref_addr)
        return 0

    # cycle through function instructions
    # that contain a string of interest
    # and look for printf or equivilant calls using the string, 
    # if we see function name, then we rename the function accordingly
    #addr = xref_addr # we start from the xref
    # ^ for Hydra, we started from the beginning of the function
    # but starting from the xref address seems to be yield less 
    # false positives
    while addr < func.endEA and instcount < 15:
        mnem = GetMnem(addr)
        oper = GetOpnd(addr, 0) 
        if(oper == ""):
            addr = NextHead(addr)
            instcount += 1
            continue

        # for debugging
        #print("%s %s" % (mnem, oper))
        # debug with sub_3AF6CC

        # jal == mips call, change to b/bl for ARM
        # check for various calls via oper
        if(mnem == "BL" and oper == "malloc_wrapper" or oper == "Malloc_snprintf_lock" or oper == "Malloc_snprintf_unlock" or oper == "_syslog_chk" or oper == "__syslog_chk" or oper == "l_error" or oper == "_assert_fail" or oper == "__printf_chk" or oper == "__assert_fail" or oper == "puts" or oper == "l_warn_failed_assertion" or oper == "hydra_add_shutdown_hook" or oper == "rob_proxy_add_observer" or oper == "_printf_chk" or oper == "printf" or oper == "_fprintf_chk"):
            # we found a function of interest, now make sure this string is close to the function call
            return 1
        addr = NextHead(addr)
        instcount += 1
    return 0

sc = idautils.Strings()
flag  = 0
seen_funcs = []

for s in sc:
    st = str(s)
    # if this string matches the below pattern, it's probably a function name, let's check if its used in a call to
    # printf/print_module_log_print
    if(len(st) > 5 and ':' not in st and '=' not in st and '!' not in st and '&' not in st and '[' not in st and '!' not in st and '%' not in st and '.' not in st and ' ' not in st and '.h' not in st and '.c' not in st and '(' not in st and '>' not in st and '/' not in st and '\n' not in st and st.isupper() == False):
        xrefs = [x for x in XrefsTo(s.ea, flags=0)]
        if(len(xrefs) > 0):
            for x in xrefs:
                fname = GetFunctionName(x.frm)
                if(fname == ""):
                    continue;

                # note we do not rename functions that already have names!
                if(fname not in seen_funcs and fname.startswith("sub_")):
                    print("Checking func %s" % fname)
                    if(printf_follow(x.frm)):
                        addr = idaapi.get_func(x.frm).startEA #int(fname.split('sub_')[1], 16)
                        print("--- [+] Renaming %s (%x) to %s" % (fname, addr, st))
                        
                        ## don't rename as we're debugging
                        idaapi.set_name(addr, st, idaapi.SN_NOWARN | idaapi.SN_NOCHECK | idaapi.SN_FORCE)

                        # if we've renamed, track it, so we don't rename it again when we see a later xref!
                        seen_funcs.append(fname) # for now
                        seen_funcs.append(st)

print("[+] Done")
