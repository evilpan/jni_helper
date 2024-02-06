#---------------------------------------------------------------------
# jni_helper.py - IDA JNI Helper plugin
#---------------------------------------------------------------------
import ida_typeinf
import idautils
import idaapi
import idc

import os
import sys
import json

def log(fmt, *args):
    print "[+]", fmt % args


def load_methods():
    sigfile = idc.AskFile(0, "*.json", "Select json signature file")
    log("loading signature file: %s", sigfile)

    with open(sigfile, 'r') as f:
        data = json.load(f)

    directMethods = {}
    for clz, methods in data["dexInfo"].items():
        for method in methods:
            args = ", ".join(method["args"])
            directMethods[method["mangle"]] = (method["ret"], args)
    log("loaded %d methods from JSON", len(directMethods))
    return directMethods


def is_jni_header_loaded():
    # not work as expected:
    # return idaapi.get_struc_id('JNIInvokeInterface_') != idaapi.BADADDR
    ret = None
    try:
        ret = idc.parse_decl('JNIEnv *env', idc.PT_SILENT)
    except Exception as e:
        return False
    return ret is not None


def load_jni_header():
    jni_h = idc.AskFile(0, "*.h", "Select JNI header file")
    idaapi.idc_parse_types(jni_h, idc.PT_FILE)


def apply_signature(ea, sig):
    name = idc.GetFunctionName(ea)
    ret, args = sig
    log('apply 0x%x %s', ea, name)
    decl = '{} {}({})'.format(ret, name, args)
    # log(decl)
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    # idc.set_name(ea, name)
    idc.apply_type(ea, prototype_details)


def main():
    if not is_jni_header_loaded():
        idaapi.warning('Please load jni.h first')
        load_jni_header()
    st = idc.set_ida_state(idc.IDA_STATUS_WORK)
    infos = load_methods()
    failed = []
    succ = 0
    for ea in idautils.Functions():
        fname = idc.GetFunctionName(ea)
        if fname.startswith('Java_') or fname in ['JNI_OnLoad', 'JNI_OnUnload']:
            sig = infos.get(fname)
            if sig is None:
                failed.append(fname)
            else:
                succ += 1
                apply_signature(ea, sig)
    idaapi.info('JNI functions loaded, {} success. {} failed. \n{}'.format(
        succ,
        len(failed),
        '\n'.join(failed)
    ))
    idc.set_ida_state(st)


class JNIHelperPlugin(idaapi.plugin_t):
    """
    JNI Helper plugin class
    """
    flags = 0
    comment = "Import JSON Signature file"
    help = "Apply JSON Signature to JNI functions"
    wanted_name = "JNI Helper"
    wanted_hotkey = "Ctrl-Alt-j"
    
    def init(self):
        log("plugin init")
        return idaapi.PLUGIN_OK 

    def run(self, arg):
        """
        :param arg: Integer, a non-zero value enables auto-run feature for
             IDA batch (no gui) processing mode. Default is 0.
        """
        log("plugin run")
        main()

    def term(self):
        log("plugin term")


def PLUGIN_ENTRY():
    return JNIHelperPlugin()
