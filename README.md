JNI Helper
===

Find JNI function signatures from APK and then load to your decompiler tools!


# Usage

1. use [JadxFindJNI.jar][JadxFindJNI] to generate signature.json
2. load signature.json into Ghidra/IDA/Radare2

# Ghidra Plugin

Install:
```sh
$ make ghidra
```

Load:
```
Window -> Script Manager -> Run Script jni_helper.py 
```
