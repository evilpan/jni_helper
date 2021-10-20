# JNI Helper for IDA

Load JNI function signatures from JSON file and apply to IDA-Pro

# Install

copy jni_helper.py to IDA plugin dir.

IDA user plugin directory:
```python
os.path.join(idaapi.get_user_idadir(), "plugins")
```

General plugin directory:
- macOS: $IDA_HOME/ida.app/Contents/MacOS/plugins
- Windows: %IDA_HOME%\plugins

# Load

```
Edit -> Plugins -> JNI Helper
```

Or you can just `Alt + F7` to run the script.

For `IDA Pro 7.4+`, use `jni_helper3.py` instead.

Logging:
```
[+] plugin init
[+] plugin run
[+] loading signature file: /Users/root/app-debug.json
[+] loaded 14 methods from JSON
[+] apply 0x9f8 JNI_OnLoad
[+] apply 0xa90 JNI_OnUnload
[+] apply 0xabc Java_com_evilpan_demojni_MainActivity_c_1stringFromJNI
[+] apply 0xae4 Java_com_evilpan_demojni_MainActivity_c_1testOverload__
[+] apply 0xb70 Java_com_evilpan_demojni_MainActivity_c_1testOverload__I
[+] apply 0xca8 Java_com_evilpan_demojni_MainActivity_c_1testOverload__JFD
[+] apply 0xdb0 Java_com_evilpan_demojni_MainActivity_c_1testStatic
[+] apply 0xe78 Java_com_evilpan_demojni_MainActivity_c_1testClass
[+] apply 0xf98 Java_com_evilpan_demojni_MainActivity_c_1testArray
```

Before:

![1][1]

After:

![2][2]

# Links

- [hex-rays/idapython_docs][doc]
- [hex-rays/sdkdoc][sdk]
- [hex-rays/ida74_idapython_no_bc695_porting_guide][port]
- [IDAPython cheatsheet][snip]

[doc]: https://www.hex-rays.com/products/ida/support/idapython_docs/
[sdk]: https://www.hex-rays.com/products/ida/support/sdkdoc/index.html
[port]: https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
[flare]: https://github.com/fireeye/flare-ida
[snip]: https://gist.github.com/icecr4ck/7a7af3277787c794c66965517199fc9c
[pal]: https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/

[1]: https://img-blog.csdnimg.cn/20201005164101129.png
[2]: https://img-blog.csdnimg.cn/20201005164352403.png
