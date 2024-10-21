#include <jni.h>
#include <string>
#include <android/log.h>

#define TAG "JNI_CPP"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

__attribute__((always_inline)) static inline jstring encode(JNIEnv *env, jstring data) {
    jclass utilClass = env->FindClass("com/evilpan/demoapk/Util");
    if (utilClass == nullptr) {
        LOG("class not found");
        return data;
    }
    jmethodID encodeMethod = env->GetStaticMethodID(
            utilClass, "encode", "(Ljava/lang/String;)Ljava/lang/String;");
    if (encodeMethod == nullptr) {
        LOG("method not found");
        return data;
    }
    jstring result = (jstring) env->CallStaticObjectMethod(utilClass, encodeMethod, data);
    return result;
}

static jstring cpp_dynamic1(JNIEnv *env, jobject thiz, jstring string) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return encode(env, string);
}

static jstring cpp_dynamic2(JNIEnv *env, jobject thiz, jstring string) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return encode(env, string);
}

static jstring cpp_dynamic3(JNIEnv *env, jclass clazz, jstring string) {
    LOG("%s(env=%p, clazz=%p)", __FUNCTION__, env, clazz);
    return encode(env, string);
}

extern "C"
JNIEXPORT int JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOG("JNI_OnLoad(vm=%p, reserved=%p)", vm, reserved);
    JNINativeMethod methods[] = {
            {"cppDynamic1", "(Ljava/lang/String;)Ljava/lang/String;", (void *)&cpp_dynamic1},
            {"cppDynamic2", "(Ljava/lang/String;)Ljava/lang/String;", (void *)&cpp_dynamic2},
            {"cppDynamic3", "(Ljava/lang/String;)Ljava/lang/String;", (void *)&cpp_dynamic3},
    };
    JNIEnv *env = nullptr;
    vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    jclass cls = env->FindClass("com/evilpan/demoapk/Facade");
    env->RegisterNatives(cls, methods, sizeof(methods) / sizeof(methods[0]));
    return JNI_VERSION_1_6;
}

extern "C"
JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved) {
    LOG("JNI_OnUnload(vm=%p, reserved=%p)", vm, reserved);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_evilpan_demoapk_FacadeCpp_stringFromJNI(JNIEnv *env, jobject thiz) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeCpp_testOverload__(JNIEnv *env, jobject thiz) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 0;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeCpp_testOverload__I(JNIEnv *env, jobject thiz, jint i) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 0;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeCpp_testOverload__JFD(JNIEnv *env, jobject thiz, jlong i, jfloat j,
                                                     jdouble k) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 0;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeCpp_testStatic(JNIEnv *env, jclass clazz, jint i) {
    LOG("%s(env=%p, class=%p)", __FUNCTION__, env, clazz);
    return 0;
}
extern "C"
JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeCpp_testClass(JNIEnv *env, jobject thiz, jobject context) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    jclass cls = env->GetObjectClass(thiz);
    jmethodID callback = env->GetStaticMethodID(
            cls, "static_callback", "(Ljava/lang/String;)V");
    jclass Context = env->GetObjectClass(context);
    jmethodID method = env->GetMethodID(Context, "getDataDir", "()Ljava/io/File;");
    jobject file = env->CallObjectMethod(context, method);
    jstring ret = (jstring) env->CallObjectMethod(
            file,
            env->GetMethodID(
                    env->FindClass("java/io/File"),
                    "getAbsolutePath",
                    "()Ljava/lang/String;"));
    env->CallStaticVoidMethod(cls, callback, ret);
    return env->GetStringUTFLength(ret);
}
extern "C"
JNIEXPORT void JNICALL
Java_com_evilpan_demoapk_FacadeCpp_testArray(JNIEnv *env, jobject thiz, jintArray input) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
}
