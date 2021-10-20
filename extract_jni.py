#!/usr/bin/env python3
import json
from datetime import datetime
from collections import Counter
from typing import Iterable, Iterator, List, Dict

from androguard.misc import APK
from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.dvm import DalvikVMFormat, ClassDefItem, EncodedMethod
from androguard.decompiler.dad.util import TYPE_DESCRIPTOR

from rich.progress import track
from rich.console import Console


def get_type(atype):
    """
    Retrieve the java type of a descriptor (e.g : I -> jint)
    """
    res = TYPE_DESCRIPTOR.get(atype)
    if res:
        if res == 'void':
            return res
        else:
            return 'j' + res
    if atype[0] == 'L':
        if atype == 'Ljava/lang/String;':
            res = 'jstring'
        else:
            res = 'jobject'
    elif atype[0] == '[':
        if len(atype) == 2 and atype[1] in 'ZBSCIJFD':
            res = TYPE_DESCRIPTOR.get(atype[1])
        else:
            res = 'object'
        res = 'j%sArray' % res
    else:
        print('Unknown descriptor: "%s".', atype)
        res = 'void'
    return res


def mangle_unicode(str):
    out = ''
    for s in str:
        i = ord(s)
        if i >= 0 and i < 128:
            out += s
        else:
            out += '_0%04x' % i
    return out


def escape(name: str):
    name = name.replace('_', '_1')
    name = name.replace(';', '_2')
    name = name.replace('[', '_3')
    name = mangle_unicode(name)
    name = name.replace('/', '_')
    return name


class JNIMethod(object):
    def __init__(self, jclass, name, args, ret, static=False, overload=False):
        self.jclass = jclass # fullname: e.g com.evilpan.Foo
        self.name = name # method name
        self.args = args # list of smali type
        self.ret = ret # smali type
        self.static = static
        self.overload = overload

    @classmethod
    def from_method(cls, em: EncodedMethod) -> 'JNIMethod':
        flags = em.get_access_flags_string().split()
        if 'native' not in flags:
            return None
        # Can be calculated this in the outside loop, but it doesn't really matters...
        jclass = str(em.get_class_name()[1:-1].replace('/', '.'))
        name = str(em.name)
        args, ret = em.get_descriptor()[1:].rsplit(')', 1)
        args = str(args).split()
        ret = str(ret)
        return cls(jclass, name, args, ret, static='static' in flags)

    @property
    def native_name(self):
        """
        return crosponding native C symbol name
        https://docs.oracle.com/en/java/javase/16/docs/specs/jni/design.html
        """
        name = escape(self.jclass + '.' + self.name)
        name = "Java_" + name.replace('.', '_')
        if self.overload:
            sig = "".join(self.args)
            sig = escape(sig)
            name = name + "__" + sig
        return name

    @property
    def native_args(self):
        # NOTE: ghidra pointer and type require space inside 
        args = [('JNIEnv *', 'env')]
        if self.static:
            args.append(('jclass', 'clazz'))
        else:
            args.append(('jobject', 'this'))
        return args + [(get_type(arg), 'a%d' % (i+1)) for i, arg in enumerate(self.args)]

    @property
    def native_ret(self):
        return get_type(self.ret)

    def __repr__(self):
        return "{}{}({}){}".format(
            "static " if self.static else "",
            self.name,
            " ".join(self.args),
            self.ret,
        )

    def __str__(self):
        return "JNIEXPORT {} JNICALL {} ({})".format(
            self.native_ret, self.native_name,
            ", ".join(map(lambda a: a[0] + ' ' + a[1], self.native_args))
        )


def parse_class_def(cdef: ClassDefItem) -> List[JNIMethod]:
    jms = []
    names = []
    for em in cdef.get_methods():
        jm = JNIMethod.from_method(em)
        if jm is None:
            continue
        jms.append(jm)
        names.append(jm.name)
    n = Counter(names)
    for jm in jms:
        if n.get(jm.name) > 1:
            jm.overload = True
    return jms


def parse_dx(dx: Analysis) -> Iterator[JNIMethod]:
    for cx in dx.get_internal_classes():
        for jm in parse_class_def(cx.get_class()):
            yield jm


def parse_apk(apkfile, outfile=None):
    console = Console()
    t0 = datetime.now()
    a = APK(apkfile, skip_analysis=True)
    out = {
        "JNI_OnLoad": [
            "jint", "JavaVM * vm, void * reserved"
        ],
        "JNI_OnUnload": [
            "void", "JavaVM * vm, void * reserved"
        ],
    }
    dexes = list(a.get_all_dex())
    total = len(dexes)
    num_class = 0
    for i, dex in track(enumerate(dexes), 'Analyzing...', console=console, total=total):
        idx = i + 1
        try:
            console.log("Parsing DEX {}/{} ({} bytes) ...".format(idx, total, len(dex)))
            df = DalvikVMFormat(dex)
        except Exception as e:
            console.log("[bold red]Failed parsing DEX {}[/bold red]: {}".format(idx, e))
            continue
        for cdef in df.get_classes():
            num_class += 1
            methods = parse_class_def(cdef)
            for m in methods:
                out[m.native_name] = [
                    m.native_ret,
                    ", ".join("%s %s" % (t, n) for t, n in m.native_args)
                ]
    console.log("Aanlyzed {} classes, cost: {}".format(
        num_class, datetime.now() - t0))
    console.log("Found {} JNI methods.".format(len(out)))
    if not outfile:
        # console.print_json(data=out)
        console.print(out)
    else:
        with open(outfile, 'w') as f:
            json.dump(out, f, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('apk', help='/path/to/apk')
    parser.add_argument('-o', dest='outfile', help='save JNI methods as formatted json file')
    args = parser.parse_args()
    parse_apk(args.apk, args.outfile)
