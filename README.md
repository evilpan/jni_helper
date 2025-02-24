JNI Helper
===

![CI](https://github.com/evilpan/jni_helper/workflows/CI/badge.svg)

Find JNI function signatures in APK and apply to reverse tools.

# Basic Usage

1. Use [extract_jni.py](./extract_jni.py) to generate `signature.json`
2. Load `signature.json` into Ghidra/IDA/BinaryNinja

## extract_jni.py

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

Example:
```sh
./extract_jni.py app-debug.apk -o signature.json
```

![extract][extract]

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

## Binary Ninja Plugin

see [Binary Ninja](./binary_ninja).

Type   |  Image
:-----:|:------------:
Before |  ![b2][b2]
After  |  ![b4][b4]

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

[i1]: https://i-blog.csdnimg.cn/blog_migrate/fcb5e94e699c7cfd9cdac7d07dcee487.png
[i2]: https://i-blog.csdnimg.cn/blog_migrate/e7b4338d4d4e1f88ffe4335f75f9292e.png
[g1]: https://i-blog.csdnimg.cn/blog_migrate/0ba333be526ff368fd0b21fb86cb6253.png
[g2]: https://i-blog.csdnimg.cn/blog_migrate/f2deaf1b343bdb69650ff9b6612b1466.png



[b1]: https://i-blog.csdnimg.cn/direct/1a68a50684ef4151a7c6b7442599f295.png
[b2]: https://i-blog.csdnimg.cn/direct/56fb96fdf46a42b8ad5a79367df0b78f.png
[b3]: https://i-blog.csdnimg.cn/direct/6de69105b83c4a9197cbad513ed4fe94.png
[b4]: https://i-blog.csdnimg.cn/direct/58a77ec9f9a54e86871b5325ab5f1333.png

[extract]: https://i-blog.csdnimg.cn/direct/df84d62729034202ad172be7db387e6a.png
