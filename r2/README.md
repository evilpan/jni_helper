# JNI Helper for Radare2

WIP

# Usage

```sh
$ JNI_OUT=../demo/app-debug.json r2 -i jni_helper.py ../demo/lib/armeabi-v7a/libnative-c.so
Cannot determine entrypoint, using 0x000009a4.
[+] loading signature file: ../demo/app-debug.json
[+] loaded 14 methods from JSON
[+] apply 0xabc @ Java_com_evilpan_demojni_MainActivity_c_1stringFromJNI
[+] apply 0xb70 @ Java_com_evilpan_demojni_MainActivity_c_1testOverload__I
[+] apply 0xa90 @ JNI_OnUnload
[+] apply 0xf98 @ Java_com_evilpan_demojni_MainActivity_c_1testArray
[+] apply 0xe78 @ Java_com_evilpan_demojni_MainActivity_c_1testClass
[+] apply 0xca8 @ Java_com_evilpan_demojni_MainActivity_c_1testOverload__JFD
Cant find get by name arg3
[+] apply 0x9f8 @ JNI_OnLoad
[+] apply 0xae4 @ Java_com_evilpan_demojni_MainActivity_c_1testOverload__
[+] apply 0xdb0 @ Java_com_evilpan_demojni_MainActivity_c_1testStatic
 -- In soviet Afghanistan, you debug radare2!
[0x00000db0]>
```

# TODO

- [ ] use `afvR` to rename local variables
- [ ] use `afs` to change function signature (radare [issue#17432][17432])
- [ ] use `tl` to link types

# LINKS

[49]: https://github.com/radareorg/r2ghidra/issues/49
[17432]: https://github.com/radareorg/radare2/issues/17432
