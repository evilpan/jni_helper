JNI Helper
===

![CI](https://github.com/evilpan/jni_helper/workflows/CI/badge.svg)

Find JNI function signatures in APK and apply to reverse tools.

# Basic Usage

1. Use [extract_jni.py](./extract_jni.py) to generate signature.json
2. Load signature.json into Ghidra/IDA/Radare2

## extract_jni.py

![extract][extract]

Install dependences:
```
pip3 install -r requirements.txt
```

Usage:
```sh
$ ./extract_jni.py -h
usage: extract_jni.py [-h] [-j WORKERS] [-o OUTFILE] apk

positional arguments:
  apk         /path/to/apk

optional arguments:
  -h, --help  show this help message and exit
  -j WORKERS  parse apk with multiple workers(processes) (default: 8)
  -o OUTFILE  save JNI methods as formatted json file (default: stdout)
```

## Ghidra Plugin

See [Ghidra](./ghidra).

Before      |  After    
:----------:|:------------:
![g1][g1]   |  ![g2][g2]


## IDA Plugin

See [IDA](./ida).

Before      |  After    
:----------:|:------------:
![i1][i1]   |  ![i2][i2]

## Binary Ninja

see [Binary Ninja](./binaryninja).

Before      |  After    
:----------:|:------------:
![b2][b2]   |  ![b4][b4]

## Radare2 Plugin

> WIP, see [Radare2](./r2)

# Demo

Tested with [demo APK](demo_apk).

```sh
cd demo_apk
./gradlew assembleDebug
```

# TODO

- [x] support both C/C++ JNI functions
- [x] support overloaded JNI functions
- [x] remove Jadx dependence, all in Python
- [x] Add BinaryNinja plugin
- [ ] support [env->RegisterNatives][reg] JNI functions

# LINKS

- [android native-libraries][reg]
- [安卓逆向之自动化JNI静态分析][blog]

[blog]: https://evilpan.com/2020/10/07/jni-helper/
[reg]: https://developer.android.com/training/articles/perf-jni#native-libraries
[ayrx]: https://github.com/Ayrx/JNIAnalyzer
[dist]: https://github.com/evilpan/jni_helper/releases

[i1]: https://img-blog.csdnimg.cn/20201005164101129.png
[i2]: https://img-blog.csdnimg.cn/20201005164352403.png
[g1]: https://img-blog.csdnimg.cn/20201005152933443.png
[g2]: https://img-blog.csdnimg.cn/20201005153107550.png

[b1]: https://i-blog.csdnimg.cn/direct/1a68a50684ef4151a7c6b7442599f295.png
[b2]: https://i-blog.csdnimg.cn/direct/56fb96fdf46a42b8ad5a79367df0b78f.png
[b3]: https://i-blog.csdnimg.cn/direct/6de69105b83c4a9197cbad513ed4fe94.png
[b4]: https://i-blog.csdnimg.cn/direct/58a77ec9f9a54e86871b5325ab5f1333.png

[extract]: https://img-blog.csdnimg.cn/direct/b7dbfbe6b3744b56a6d66079db8ebbb8.png
