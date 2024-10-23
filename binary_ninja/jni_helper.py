import json
import os
from typing import List, Dict

from binaryninja import TypeParser, BinaryView
from binaryninja.typeparser import TypeParserResult
from binaryninja.types import StructureMember, FunctionType
from binaryninja.function import Function
from binaryninja.interaction import (
    OpenFileNameField,
    get_form_input,
)

def log(msg, *args, **kwargs):
    print("[+]", msg, *args, **kwargs)

class JNIHelper:

    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.jni_header = ""
        self.pr: TypeParserResult = None
        self.sigmap: Dict[str, FunctionType] = {}

    def start(self):
        log(f"plugin start, bv={self.bv}")
        if not self.init_header():
            return
        self.apply_signatures()
        self.fix_cpp_symbols()

    def fix_cpp_symbols(self):
        """
        fix incorrect signatures for `_JNIEnv::` in PLT,
        for example `_JNIEnv::CallObjectMethod`
        """
        if not self.pr:
            return
        funcs: List[Function] = []
        for fn in self.bv.functions:
            name = fn.symbol.short_name
            if name.startswith("_JNIEnv::"):
                funcs.append(fn)
        if not funcs:
            log("not cpp library, skip")
            return
        for fn in funcs:
            vtype = self.sigmap.get(fn.symbol.short_name)
            if vtype is None:
                log(f"WARN: no signature for {name}")
                continue
            fn.type = vtype
            log(f"cpp fix 0x{fn.start:x} {fn.symbol.short_name}")

    def init_header(self):
        jni_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "headers", "jni.h")
        if not os.path.exists(jni_file):
            jni_file = self.choose_file("jni.h not found, choose one")
            if jni_file is None:
                return
        with open(jni_file, 'r') as f:
            self.jni_header = f.read()
        pr = self.parse_source(self.jni_header, "jni.h")
        if not pr:
            return False
        self.pr = pr
        log("init_header success.")
        for pt in self.pr.types:
            self.bv.define_user_type(pt.name, pt.type)
            if pt.name == 'JNINativeInterface_':
                member: StructureMember = None
                for member in pt.type.members[4:]:
                    name = f"_JNIEnv::{member.name}"
                    self.sigmap[name] = member.type.children[0]
                log("loaded {} JNI interface".format(len(self.sigmap)))
        return True

    def parse_source(self, source, name="<source>"):
        options = ["-fdeclspec"]
        result, errors = TypeParser.default.parse_types_from_source(
                source, name, self.bv.platform,
                existing_types=self.bv,
                options=options
        )
        if result is None:
            log("parse error:")
            for err in errors:
                log(err, end='')
            return None
        return result

    def choose_file(self, desc, title="File"):
        fd = OpenFileNameField(desc)
        if get_form_input([fd], title):
            return fd.result
        return None

    def apply_signatures(self):
        file = self.choose_file("signature.json from extract_jni.py")
        if not file:
            return
        with open(file, 'r') as f:
            meta = json.load(f)
        decls = ""
        func_map: Dict[str, Function] = {}
        for cls, methods in meta["dexInfo"].items():
            for method in methods:
                mangle = method["mangle"]
                found = self.bv.get_functions_by_name(mangle)
                if not found:
                    continue
                func = found[0]
                func_map[mangle] = func
                # skip those already defined
                ret = method["ret"]
                args = ",".join(method["args"])
                line = f"{ret} {mangle}({args})"
                if cls == "__COMMON__":
                    continue
                decls += line + ";\n"
        pr = self.parse_source(decls, "jni_ext.h")
        if pr is None:
            return
        for pf in pr.functions:
            if pf.name not in func_map:
                continue
            func = func_map[pf.name]
            log(f"fix 0x{func.start} {pf.name} -> {pf.type}")
            func.type = pf.type
            func.reanalyze()


jh = JNIHelper(bv)
jh.start()
