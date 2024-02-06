#include <jni.h>
#include <android/log.h>

#define TAG "JNI"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int dynamic_c(JNIEnv *env, jobject thiz) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 42;
}

static void dynamic_c_private(JNIEnv *env, jobject thiz, jint i) {
    LOG("%s(env=%p, this=%p, i=%d)", __FUNCTION__, env, thiz, i);
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOG("JNI_OnLoad(vm=%p, reserved=%p)", vm, reserved);
    JNIEnv *env = NULL;
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (env) {
        LOG("env=%p", env);
    } else {
        LOG("failed to get JNIEnv");
    }
    JNINativeMethod methods[] = {
            {"testDynamic",    "()I",                    (void *)&dynamic_c},
            {"testDynamic1",    "(I)V",                    (void *)&dynamic_c_private}
    };
    jclass cls = (*env)->FindClass(env, "com/evilpan/demoapk/FacadeC");
    (*env)->RegisterNatives(env, cls, methods, 2);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved) {
    LOG("JNI_OnUnload(vm=%p, reserved=%p)", vm, reserved);
}

JNIEXPORT jstring JNICALL
Java_com_evilpan_demoapk_FacadeC_stringFromJNI(JNIEnv *env, jobject thiz) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return (*env)->NewStringUTF(env, "Hello from C");
}

JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeC_testOverload__(JNIEnv *env, jobject thiz) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeC_testOverload__I(JNIEnv *env, jobject thiz, jint i) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeC_testOverload__JFD(JNIEnv *env, jobject thiz, jlong i, jfloat j,
                                                   jdouble k) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeC_testStatic(JNIEnv *env, jclass clazz, jint i) {
    LOG("%s(env=%p, clazz=%p)", __FUNCTION__, env, clazz);
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_evilpan_demoapk_FacadeC_testClass(JNIEnv *env, jobject thiz, jobject context) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_evilpan_demoapk_FacadeC_testArray(JNIEnv *env, jobject thiz, jintArray input) {
    LOG( "%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
}