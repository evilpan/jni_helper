JNI Helper
===

![CI](https://github.com/evilpan/jni_helper/workflows/CI/badge.svg)

Find JNI function signatures in APK and apply to reverse tools.

# Basic Usage

1. Use [JadxFindJNI.jar](JadxFindJNI) to generate signature.json
2. Load signature.json into Ghidra/IDA/Radare2

## JadxFindJNI.jar

Build:
```
$ make jni
```

Or you can just download the [latest release][dist].

Usage:
```sh
$ java -jar JadxFindJNI/JadxFindJNI.jar
Usage: JadxFindJNI.jar <file.apk> <output.json>
```

## Ghidra

See [Ghidra](./ghidra)

Before:

![g1][g1]

After:

![g2][g2]


## IDA

See [IDA](./ida)

Before:

![i1][i1]

After:

![i2][i2]


## Radare2

See [Radare2](./r2)

# Demo

Tested with [app-debug.apk](./demo).

```sh
$ make demo
```


# TODO

- [x] support both C/C++ JNI functions
- [x] support overloaded JNI functions
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
