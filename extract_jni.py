#!/usr/bin/env python3
import json
import multiprocessing
from datetime import datetime
from collections import Counter, namedtuple
from typing import Iterable, Iterator, List, Dict

from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes.dvm import DalvikVMFormat, ClassDefItem, EncodedMethod
from androguard.decompiler.dad.util import TYPE_DESCRIPTOR

from rich.progress import track
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
)

DexFile = namedtuple('DexFile', ['name', 'data'])

JNI_COMMON = {
    "JNI_OnLoad": [
        "jint", "JavaVM * vm, void * reserved"
    ],
    "JNI_OnUnload": [
        "void", "JavaVM * vm, void * reserved"
    ],
}

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

    @property
    def as_dict(self):
        return { self.native_name: [
            self.native_ret,
            ", ".join("%s %s" % (t, n) for t, n in self.native_args)
        ]}

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


def parse_dx(dx: Analysis, fn_match=None, outfile=None):
    console = Console()
    out = {}
    out.update(JNI_COMMON)
    count = 0
    for cx in dx.get_internal_classes():
        methods = parse_class_def(cx.get_class())
        count += 1
        if not methods:
            continue
        cname = methods[0].jclass
        if fn_match and not fn_match(cname):
            continue
        for m in methods:
            out.update(m.as_dict)
    console.log(f"Parse {count} classes.")
    console.log(f"Found {len(out)} JNI methods.")
    if not outfile:
        console.print_json(data=out)
    else:
        with open(outfile, 'w') as f:
            json.dump(out, f, indent=2, ensure_ascii=False)


def extract_dex_files(apkfile) -> Iterator[DexFile]:
    from zipfile import ZipFile
    z = ZipFile(apkfile)
    for info in z.infolist():
        if info.filename.endswith('.dex'):
            yield DexFile(info.filename, z.read(info))


def parse_dex_proc(dex: DexFile):
    out = {}
    count = 0
    try:
        df = DalvikVMFormat(dex.data)
    except Exception as e:
        return dex, count, e
    for cdef in df.get_classes():
        count += 1
        methods = parse_class_def(cdef)
        if not methods:
            continue
        className = methods[0].jclass
        out[className] = {}
        for m in methods:
            out[className].update(m.as_dict)
    return dex, count, out


def parse_apk(apkfile, workers, fn_match=None, outfile=None):
    console = Console()
    console.log(f"Parsing {apkfile} with {workers} workers ...")
    dexes = list(extract_dex_files(apkfile))
    console.log(f"Found {len(dexes)} DEX file.")
    total = sum(map(lambda d: len(d.data), dexes))
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(
            complete_style='bar.complete',
            finished_style='bar.finished',
            pulse_style='bar.pulse',
        ),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        TimeElapsedColumn(),
        console=console,
    )
    out = {}
    out.update(JNI_COMMON)
    num_classes = 0
    t0 = datetime.now()
    with progress:
        task = progress.add_task("Analyzing...", total=total)
        with multiprocessing.Pool(workers) as pool:
            result = pool.imap(parse_dex_proc, dexes)
            for dex, count, res in result:
                if count == 0:
                    console.log("Parse {} ({} bytes) [bold red]failed: {}".format(
                        dex.name, len(dex.data), res))
                    continue
                console.log("Parse {} ({} bytes), found {} classes.".format(
                    dex.name, len(dex.data), count))
                num_classes += count
                progress.update(task, advance=len(dex.data))
                for cname, data in res.items():
                    if fn_match and not fn_match(cname):
                        continue
                    out.update(data)
    console.log("Aanlyzed {} classes, cost: {}".format(
        num_classes, datetime.now() - t0))
    console.log("Found {} JNI methods.".format(len(out)))
    if not outfile:
        console.print_json(data=out)
    else:
        with open(outfile, 'w') as f:
            json.dump(out, f, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('apk', help='/path/to/apk')
    parser.add_argument('-j', dest='workers', type=int, default=multiprocessing.cpu_count(), help='parse apk with multiple workers(processes)')
    parser.add_argument('-o', dest='outfile', help='save JNI methods as formatted json file')
    args = parser.parse_args()
    parse_apk(args.apk, args.workers, outfile=args.outfile)