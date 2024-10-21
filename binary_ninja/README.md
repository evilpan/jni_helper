# Load

File -> Run Script


# Logging

```
[+] plugin start, bv=<BinaryView: '/root/jni_helper/assets/lib/arm64-v8a/libdemoc.so', len 0x2a88>
[+] init_header done.
[+] fix 0x3708 JNI_OnLoad -> jint(JavaVM* vm, void* reserved)
[+] fix 0x4980 JNI_OnUnload -> void(JavaVM* vm, void* reserved)
[+] fix 0x5388 Java_com_evilpan_demoapk_FacadeC_testStatic -> jint(JNIEnv* env, jclass clazz, jint a1)
[+] fix 0x5044 Java_com_evilpan_demoapk_FacadeC_stringFromJNI -> jstring(JNIEnv* env, jobject thiz)
[+] fix 0x5916 Java_com_evilpan_demoapk_FacadeC_testArray -> void(JNIEnv* env, jobject thiz, jintArray a1)
[+] fix 0x5468 Java_com_evilpan_demoapk_FacadeC_testClass -> jint(JNIEnv* env, jobject thiz, jobject a1)
[+] fix 0x5144 Java_com_evilpan_demoapk_FacadeC_testOverload__ -> jint(JNIEnv* env, jobject thiz)
[+] fix 0x5220 Java_com_evilpan_demoapk_FacadeC_testOverload__I -> jint(JNIEnv* env, jobject thiz, jint a1)
[+] fix 0x5300 Java_com_evilpan_demoapk_FacadeC_testOverload__JFD -> jint(JNIEnv* env, jobject thiz, jlong a1, jfloat a2, jdouble a3)
```

High Level IL:

Before =>

![b1][b1]

After =>

![b3][b3]

Pseudo C:

Before =>

![b2][b2]

After =>

![b4][b4]


[b1]: https://i-blog.csdnimg.cn/direct/1a68a50684ef4151a7c6b7442599f295.png
[b2]: https://i-blog.csdnimg.cn/direct/56fb96fdf46a42b8ad5a79367df0b78f.png
[b3]: https://i-blog.csdnimg.cn/direct/6de69105b83c4a9197cbad513ed4fe94.png
[b4]: https://i-blog.csdnimg.cn/direct/58a77ec9f9a54e86871b5325ab5f1333.png
