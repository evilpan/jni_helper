#---------------------------------------------------------------------
# jni_helper3.py - IDA JNI Helper plugin for IDA-Pro 7.4+
# https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
#---------------------------------------------------------------------
import ida_kernwin
import ida_typeinf
import idautils
import idaapi
import idc

import os
import sys
import json


def log(fmt, *args):
    print("[+]", fmt % args)


def load_methods():
    sigfile = ida_kernwin.ask_file(0, "*.json", "Select json signature file")
    log("loading signature file: %s", sigfile)

    with open(sigfile, 'r') as f:
        infos = json.load(f)

    log("loaded %d methods from JSON", len(infos))
    return infos


def is_jni_header_loaded():
    # not work as expected:
    # return idaapi.get_struc_id('JNIInvokeInterface_') != idaapi.BADADDR
    ret = idc.parse_decl('JNIEnv *env', idc.PT_SILENT)
    return ret is not None


def load_jni_header():
    jni_h = ida_kernwin.ask_file(0, "*.h", "Select JNI header file")
    idaapi.idc_parse_types(jni_h, idc.PT_FILE)


def apply_signature(ea, info):
    name = idc.get_func_name(ea)
    if info is None:
        log('WARN: no info found for %s', name)
        return
    log('apply 0x%x %s', ea, name)
    decl = '{} {}(JNIEnv* env, '.format(info['returnType'], name)
    if info['isStatic']:
        decl += 'jclass clazz'
    else:
        decl += 'jobject thiz'
    for idx, atype in enumerate(info['argumentTypes']):
        decl += ', {} arg{}'.format(atype, idx + 1)
    decl += ')'
    # log(decl)
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    # idc.set_name(ea, name)
    idc.apply_type(ea, prototype_details)


def apply_load_unload(ea, load=True):
    name = idc.get_func_name(ea)
    log('apply 0x%x %s', ea, name)
    decl = "{} {}(JavaVM *vm, void *reserved)".format(
        "jint" if load else "void",
        "JNI_OnLoad" if load else "JNI_OnUnload"
    )
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    idc.apply_type(ea, prototype_details)


def main():
    log("plugin run")
    if not is_jni_header_loaded():
        idaapi.warning('Please load jni.h first')
        load_jni_header()
    st = idc.set_ida_state(idc.IDA_STATUS_WORK)
    infos = load_methods()
    failed = []
    succ = 0
    for ea in idautils.Functions():
        fname = idc.get_func_name(ea)
        if fname.startswith('Java_'):
            info = infos.get(fname)
            if info is None:
                failed.append(name)
            else:
                succ += 1
            apply_signature(ea, info)
        if fname == 'JNI_OnLoad':
            apply_load_unload(ea, True)
            succ += 1
        if fname == 'JNI_OnUnload':
            apply_load_unload(ea, False)
            succ += 1
    idaapi.info('JNI functions loaded, {} success. {} failed. \n{}'.format(
        succ,
        len(failed),
        '\n'.join(failed)
    ))
    idc.set_ida_state(st)


class JNIHelperPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Import JSON Signature file"
    help = "Apply JSON Signature to JNI functions"
    wanted_name = "JNI Helper"
    wanted_hotkey = "Ctrl-Alt-j"
    
    def init(self):
        log("plugin init")
        return idaapi.PLUGIN_OK 

    def term(self):
        log("plugin term")

    def run(self, arg):
        main()

def PLUGIN_ENTRY():
    return JNIHelperPlugin()

if __name__ == '__main__':
    main()
