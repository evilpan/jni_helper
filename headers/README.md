JNI Helper headers
===

Headers that could be used for reverse engineering.

# Ghidra

File -> Parse C Source

parse option:
```
-D_X86_
-D__STDC__
-D_GNU_SOURCE
-D__WORDSIZE=64
-Dva_list=void *
-D__DO_NOT_DEFINE_COMPILE
-D_Complex
-D_WCHAR_T
-D__NO_STRING_INLINES
-D__signed__
-D__extension__=""
-D_Bool="bool"
-D__GLIBC_HAVE_LONG_LONG=1
-D__need_sigset_t
-Daligned_u64=uint64_t
-Daligned_u64=uint64_t
```

# IDA-Pro

File -> Load File -> Parse C Header File

# Radare2

```sh
r2> to?
Usage: to[...]
| to -        Open cfg.editor to load types
| to <path>   Load types from C header file
| tos <path>  Load types from parsed Sdb database
```

Use [../r2/jni.h](../r2/jni.h) instead.
