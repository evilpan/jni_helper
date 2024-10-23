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
    print("[+]", fmt.format(args))


def load_methods():
    sigfile = JNI_OUT
    log(f"loading signature file: {sigfile}")

    with open(sigfile, 'r') as f:
        infos = json.load(f)
    out = {}
    for domain, methods in infos["dexInfo"].items():
        for m in methods:
            name = m['mangle']
            out[name] = m

    log(f"loaded {len(out)} methods from JSON")
    return out

def apply_signature(r2, func, info):
    addr = func['vaddr']
    name = func['name']
    if info is None:
        log(f"WARN: no info for 0x{addr} {name}")
        return
    log(f"apply 0x{addr:x} @ {name}")

    ret = info["ret"]
    args = info["args"]
    arg_names = []
    arg_types = []
    # afs not support custom type, use int32_t instead
    arg_tmp = []
    for arg in args:
        atype, aname = arg.rsplit(" ", 1)
        arg_names.append(aname)
        arg_types.append(atype)
        arg_tmp.append(
            "int32_t " + arg.split(" ", 1)[1]
        )
    decl = '{} {}({})'.format(ret, name, ",".join(arg_tmp))
    log(f"decl => {decl}")
    r2.cmd(f's {addr}; af')
    r2.cmd(f'afs {decl}')
    r2.cmd('afva') # reanalysis

    # workaround to add custom type for signature
    r2.cmd('aft')
    for i in range(len(args)):
        aname = arg_names[i]
        atype = arg_types[i]
        cmd = f'afvt {aname} "{atype}"'
        log(cmd)
        r2.cmd(cmd)
    r2.cmd('aft')


def apply_load_unload(r2, func, unload=False):
    # already loaded
    addr = func['vaddr']
    name = func['name']
    log(f"apply 0x{addr} @ {name}")
    r2.cmd(f's {addr}; af')


def main():
    if not JNI_OUT:
        log("please set JNI_OUT environment to your signature.json")
        return
    infos = load_methods()
    r2 = r2pipe.open()
    # r2.cmd('aac')
    r2.cmd(f'to {JNI_HEADER};')
    r2.cmd('e emu.str=true;')
    r2.cmd('aei;aeim;')
    for e in r2.cmdj('iEj'):
        sym = e['name']
        if sym.startswith('Java_'):
            apply_signature(r2, e, infos.get(sym))
        if sym == 'JNI_OnLoad':
            apply_load_unload(r2, e)
        if sym == 'JNI_OnUnload':
            apply_load_unload(r2, e, True)


main()
