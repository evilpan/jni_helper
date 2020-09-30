# Load JNI signature from JSON
# @author evilpan (https://evilpan.com/)
# @category JNI
import os
import json
import time

from java.io import File
from ghidra.framework import Application
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import ReturnParameterImpl


def log(fmt, *args, **kwargs):
    print "[+]", fmt % args


class TypeUtil(object):
    def __init__(self):
        self.namespace = "jni.h"
        self.plugin = state.getTool().getService(DataTypeManagerService)
        self.manager = None
        for m in self.plugin.getDataTypeManagers():
            log("manager: %s", m.getName())
            if m.getName() == self.namespace:
                log("JNI DataTypeManager already loaded: %s", m)
                self.manager = m
                break
        if self.manager is None:
            self.load_jni_h()

    def load_jni_h(self):
        gdt =  os.path.join(os.path.expanduser("~"), "ghidra_scripts", "data", self.namespace + ".gdt")
        log("loading ghidra data type from: %s", gdt)
        archive = self.plugin.openArchive(File(gdt), False)
        self.manager = archive.getDataTypeManager()
        log("loaded manager: %s", self.manager.getName())

    def _param(self, fullType, paramName):
        t = self.manager.getDataType(fullType)
        return ParameterImpl(paramName, t, currentProgram, SourceType.USER_DEFINED)

    def _ret(self, fullType):
        t = self.manager.getDataType(fullType)
        return ReturnParameterImpl(t, currentProgram)

    def jni_param(self, paramType, paramName):
        ft = "/" + self.namespace + "/" + paramType
        return self._param(ft, paramName)

    def jni_ret(self, retType):
        ft = "/" + self.namespace + "/" + retType
        return self._ret(ft)

    def apply_signature(self, addr, info):
        func = getFunctionAt(addr)
        params = []
        env = self.jni_param("JNIEnv *", "env")
        if info.get('isStatic'):
            obj = self.jni_param("jclass", "clazz")
        else:
            obj = self.jni_param("jobject", "thiz")
        params.append(env)
        params.append(obj)
        for i, t in enumerate(info.get('argumentTypes', [])):
            name = 'a' + str(i + 1)
            params.append(self.jni_param(t, name))
        ret = self.jni_ret(info.get('returnType', 'void'))
        func.updateFunction(None, ret,
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
                            SourceType.USER_DEFINED, params);

    def apply_load(self, name):
        func = getFunction(name)
        if func is None:
            return
        log("applying 0x%s %s", func.getSymbol().getAddress(), name)
        params = [
            self.jni_param("JavaVM *", "vm"),
            self._param("/void *", "reserved")
        ]
        if name == 'JNI_OnLoad':
            ret = self.jni_ret("jint")
        else:
            ret = self._ret("/void")
        func.updateFunction(None, ret,
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
                            SourceType.USER_DEFINED, params);


def load_methods():
    sigfile = askFile("Select json signature file", "Load").getAbsolutePath()
    log("loading signature file: %s", sigfile)

    with open(sigfile, 'r') as f:
        infos = json.load(f)

    log("loaded %d methods from JSON", len(infos))
    return infos


def main():
    u = TypeUtil()
    methods = load_methods()
    sm = currentProgram.getSymbolTable()
    symbols = sm.getSymbolIterator("Java_*", True)
    skipped = []
    for s in symbols:
        name = s.getName()
        addr = s.getAddress()
        info = methods.get(name, None)
        if info is None:
            skipped.append((addr, name))
            continue
        log("applying 0x%s %s", addr, name)
        u.apply_signature(addr, info)
    u.apply_load("JNI_OnLoad")
    u.apply_load("JNI_OnUnload")

    log("ignore %d symbols", len(skipped))
    for addr, name in skipped:
        log("> 0x%s %s", addr, name)

main()
