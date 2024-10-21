import json
import os
import binaryninja
from binaryninja.interaction import (
    OpenFileNameField,
    get_form_input,
    show_message_box,
)

def log(msg, *args, **kwargs):
    print("[+]", msg, *args, **kwargs)

class JNIHelper:

    def __init__(self):
        self.jni_header = ""

    def start(self):
        if not self.init_header():
            return
        self.apply_signatures()

    def init_header(self):
        options = ["-fdeclspec"]
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
        log("init_header done.")
        return True

    def parse_source(self, source, name="<source>"):
        options = ["-fdeclspec"]
        result, errors = TypeParser.default.parse_types_from_source(
                source, name, bv.platform,
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
        jni_ext = self.jni_header + "\n"
        func_map = {}
        for cls, methods in meta["dexInfo"].items():
            for method in methods:
                mangle = method["mangle"]
                found = bv.get_functions_by_name(mangle)
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
                jni_ext += line + ";\n"
        pr = self.parse_source(jni_ext, "jni_ext.h")
        if pr is None:
            return
        for pt in pr.types:
            bv.define_user_type(pt.name, pt.type)
        for pf in pr.functions:
            if pf.name not in func_map:
                continue
            func = func_map[pf.name]
            log(f"fix 0x{func.start} {pf.name} -> {pf.type}")
            func.type = pf.type
            func.reanalyze()


log(f"plugin start, bv={bv}")
jh = JNIHelper()
jh.start()
