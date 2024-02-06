# Load JNI signature from JSON
# @author evilpan (https://evilpan.com/)
# @category JNI
# @toolbar
# @menupath

import os
import json
import time
import itertools

from java.io import File
from ghidra.framework import Application
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import ReturnParameterImpl


def log(fmt, *args):
    print "[+]", fmt % args


def load_methods():
    sigfile = askFile("Select json signature file", "Load").getAbsolutePath()
    log("loading signature file: %s", sigfile)

    with open(sigfile, 'r') as f:
        out = json.load(f)

    directMethods = {}
    for clz, methods in out["dexInfo"].items():
        for method in methods:
            args = ", ".join(method["args"])
            directMethods[method["mangle"]] = (method["ret"], args)
    log("loaded %d methods from JSON", len(directMethods))
    return directMethods


class TypeUtil(object):
    def __init__(self):
        self.namespace = "jni.h"
        self.plugin = state.getTool().getService(DataTypeManagerService)
        self.manager = None
        for m in self.plugin.getDataTypeManagers():
            # log("manager: %s", m.getName())
            if m.getName() == self.namespace:
                log("JNI DataTypeManager already loaded: %s", m.getName())
                self.manager = m
                break
        if self.manager is None:
            self.loadJNIHeader()

    def loadJNIHeader(self):
        gdt =  os.path.join(os.path.expanduser("~"), "ghidra_scripts", "data", self.namespace + ".gdt")
        log("loading ghidra data type from: %s", gdt)
        archive = self.plugin.openArchive(File(gdt), False)
        self.manager = archive.getDataTypeManager()
        log("loaded manager: %s", self.manager.getName())

    def getParam(self, paramType, paramName):
        t = self.getType(paramType)
        return ParameterImpl(paramName, t, currentProgram, SourceType.USER_DEFINED)

    def getRet(self, retType):
        return ReturnParameterImpl(self.getType(retType), currentProgram)

    def getType(self, typeName):
        ns = self.namespace
        if 'void' in typeName:
            ns = ''
        fullType = os.path.join("/", ns, typeName)
        return self.manager.getDataType(fullType)

    def applySignature(self, addr, sig):
        func = getFunctionAt(addr)
        ret, args = sig
        params = []
        for tn in args.split(", "):
            if not tn:
                continue
            t, n = tn.rsplit(" ", 1)
            params.append(self.getParam(t, n))
        func.updateFunction(None, self.getRet(ret),
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
                            SourceType.USER_DEFINED, params);


def main():
    u = TypeUtil()
    methods = load_methods()
    sm = currentProgram.getSymbolTable()
    direct_symbols = sm.getSymbolIterator("Java_*", True)
    common_symbols = []
    for name in ["JNI_OnLoad", "JNI_OnUnload"]:
        func = getFunction(name)
        if func:
            common_symbols.append(func.getSymbol())
    skipped = []
    for s in itertools.chain(direct_symbols, common_symbols):
        name = s.getName()
        addr = s.getAddress()
        sig = methods.get(name, None)
        if sig is None:
            skipped.append((addr, name))
            continue
        ret, args = sig
        log("applying 0x%s %8s %s(%s)", addr, ret, name, args)
        u.applySignature(addr, sig)

    if skipped:
        log("ignore %d symbols", len(skipped))
        for addr, name in skipped:
            log("- 0x%s %s", addr, name)

main()
