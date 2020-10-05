JNI Helper for Ghidra
===

# Install

```sh
$ make install
```

# Load

```
Window -> Script Manager -> jni_helper.py (Run Script)
```

Logging:
```
jni_helper.py> Running...
[+] loading ghidra data type from: /Users/root/ghidra_scripts/data/jni.h.gdt
[+] loaded manager: jni.h
[+] loading signature file: /Users/root/app-debug.json
[+] loaded 14 methods from JSON
[+] applying 0x00010abc Java_com_evilpan_demojni_MainActivity_c_1stringFromJNI
[+] applying 0x00010f98 Java_com_evilpan_demojni_MainActivity_c_1testArray
[+] applying 0x00010e78 Java_com_evilpan_demojni_MainActivity_c_1testClass
[+] applying 0x00010ca8 Java_com_evilpan_demojni_MainActivity_c_1testOverload__JFD
[+] applying 0x00010ae4 Java_com_evilpan_demojni_MainActivity_c_1testOverload__
[+] applying 0x00010db0 Java_com_evilpan_demojni_MainActivity_c_1testStatic
[+] applying 0x00010b70 Java_com_evilpan_demojni_MainActivity_c_1testOverload__I
[+] applying 0x000109f8 JNI_OnLoad
[+] applying 0x00010a90 JNI_OnUnload
[+] ignore 1 symbols
[+] - 0x00010b70 Java_com_evilpan_demojni_MainActivity_c_1testOverload
jni_helper.py> Finished!
```

Before:

![1][1]

After:

![2][2]

[1]: https://img-blog.csdnimg.cn/20201005152933443.png
[2]: https://img-blog.csdnimg.cn/20201005153107550.png
