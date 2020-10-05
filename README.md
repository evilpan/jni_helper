JNI Helper
===

Find JNI function signatures from APK and load to reverse tools.


# Usage

1. use [JadxFindJNI.jar](JadxFindJNI) to generate signature.json
2. load signature.json into Ghidra/IDA/Radare2

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

## IDA

See [IDA](./ida)

## Radare2

See [Radare2](./r2)

# Demo

Tested with [app-debug.apk](./demo).

```sh
$ make demo
```


# TODO

- [x] support both C/C++ JNI functions
- [ ] support [env->RegisterNatives][reg] JNI functions

# Thanks

- [Ayrx/JNIAnalyzer][ayrx]

[reg]: https://developer.android.com/training/articles/perf-jni#native-libraries
[ayrx]: https://github.com/Ayrx/JNIAnalyzer
[dist]: https://github.com/evilpan/jni_helper/releases
