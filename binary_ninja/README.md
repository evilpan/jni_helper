# Load

File -> Run Script


# Logging

```
[+] plugin start, bv=<BinaryView: '/root/jni_helper/assets/lib/arm64-v8a/libdemocpp.so', len 0x4aa08>
[+] init_header success.
[+] loaded 229 JNI interface
[+] fix 0x127016 Java_com_evilpan_demoapk_FacadeCpp_testStatic -> jint(JNIEnv* env, jclass clazz, jint a1)
[+] fix 0x126388 Java_com_evilpan_demoapk_FacadeCpp_stringFromJNI -> jstring(JNIEnv* env, jobject thiz)
[+] fix 0x128136 Java_com_evilpan_demoapk_FacadeCpp_testArray -> void(JNIEnv* env, jobject thiz, jintArray a1)
[+] fix 0x127096 Java_com_evilpan_demoapk_FacadeCpp_testClass -> jint(JNIEnv* env, jobject thiz, jobject a1)
[+] fix 0x126772 Java_com_evilpan_demoapk_FacadeCpp_testOverload__ -> jint(JNIEnv* env, jobject thiz)
[+] fix 0x126848 Java_com_evilpan_demoapk_FacadeCpp_testOverload__I -> jint(JNIEnv* env, jobject thiz, jint a1)
[+] fix 0x126928 Java_com_evilpan_demoapk_FacadeCpp_testOverload__JFD -> jint(JNIEnv* env, jobject thiz, jlong a1, jfloat a2, jdouble a3)
[+] cpp fix 0x1ecfc _JNIEnv::FindClass
[+] cpp fix 0x1ed30 _JNIEnv::RegisterNatives
[+] cpp fix 0x1eedc _JNIEnv::NewStringUTF
[+] cpp fix 0x1f1b0 _JNIEnv::GetObjectClass
...
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
