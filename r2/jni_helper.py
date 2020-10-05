__author__ = 'evilpan (i@pppan.net)'
__website__ = 'https://evilpan.com/'
__description__ = 'Load JNI signature from JSON'

import os
import json
import time
import r2pipe


BASE = os.path.dirname(os.path.abspath(__file__))
JNI_HEADER = os.path.join(BASE, 'jni.h')
JNI_OUT = os.environ.get('JNI_OUT')


def log(fmt, *args):
    print "[+]", fmt % args


def load_methods():
    sigfile = JNI_OUT
    log("loading signature file: %s", sigfile)

    with open(sigfile, 'r') as f:
        infos = json.load(f)

    log("loaded %d methods from JSON", len(infos))
    return infos


def apply_signature(r2, func, info):
    addr = func['vaddr']
    name = func['name']
    if info is None:
        log("WARN: no info for 0x%x %s", addr, name)
        return
    log("apply 0x%x @ %s", addr, name)
    r2.cmd('s %d; af' % addr)

    # formatted, but radare2 not support custom structure is sigature yet
    sig = 'void %s (void* env' % name
    sig += ', int32_t ' + ('clazz' if info.get('isStatic') else 'thiz')
    for idx, at in enumerate(info.get('argumentTypes', [])):
        sig += ', int32_t arg%d' % (idx + 1)
    sig += ');'
    r2.cmd('afs ' + sig)
    r2.cmd('afva') # reanalysis

    # workaround to add custom type for signature
    r2.cmd('afvt env JNIEnv*')
    if info.get('isStatic'):
        r2.cmd('afvt clazz jclass')
    else:
        r2.cmd('afvt thiz jobject')
    for idx, at in enumerate(info.get('argumentTypes', [])):
        r2.cmd('afvt arg%d %s' % ((idx+1), at))
    r2.cmd('aft')


def apply_load_unload(r2, func, unload=False):
    # already loaded
    addr = func['vaddr']
    name = func['name']
    log("apply 0x%x @ %s", addr, name)
    r2.cmd('s %d; af' % addr)


def main():
    if not JNI_OUT:
        log("please set JNI_OUT environment to your signature.json")
        return
    infos = load_methods()
    r2 = r2pipe.open()
    # r2.cmd('aac')
    r2.cmd('to ' + JNI_HEADER)
    r2.cmd('e emu.str=true')
    r2.cmd('aei;aeim')
    for e in r2.cmdj('iEj'):
        sym = e['name']
        if sym.startswith('Java_'):
            apply_signature(r2, e, infos.get(sym))
        if sym == 'JNI_OnLoad':
            apply_load_unload(r2, e)
        if sym == 'JNI_OnUnload':
            apply_load_unload(r2, e, True)


main()
