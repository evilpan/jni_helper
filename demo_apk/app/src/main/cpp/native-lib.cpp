#include <jni.h>
#include <string>
#include <android/log.h>

#define TAG "JNI_CPP"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

int dynamic_cpp(JNIEnv *env, jobject thiz) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 42;
}

static void dynamic_cpp_private(JNIEnv *env, jobject thiz, jint i) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
}

extern "C"
JNIEXPORT int JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOG("JNI_OnLoad(vm=%p, reserved=%p)", vm, reserved);
    JNINativeMethod methods[] = {
            {"testDynamic",    "()I",                    (void *)&dynamic_cpp},
            {"testDynamic1",    "(I)V",                    (void *)&dynamic_cpp_private}
    };
    JNIEnv *env = nullptr;
    vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    jclass cls = env->FindClass("com/evilpan/demoapk/FacadeCpp");
    env->RegisterNatives(cls, methods, 2);
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
    return 0;
}
extern "C"
JNIEXPORT void JNICALL
Java_com_evilpan_demoapk_FacadeCpp_testArray(JNIEnv *env, jobject thiz, jintArray input) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
}