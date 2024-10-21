#include <jni.h>
#include <android/log.h>

#define TAG "JNI"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

__attribute__((always_inline)) static inline jstring encode(JNIEnv *env, jstring data) {
    jclass utilClass = (*env)->FindClass(env, "com/evilpan/demoapk/Util");
    if (utilClass == NULL) {
        LOG("class not found");
        return data;
    }
    jmethodID encodeMethod = (*env)->GetStaticMethodID(
            env, utilClass, "encode", "(Ljava/lang/String;)Ljava/lang/String;");
    if (encodeMethod == NULL) {
        LOG("method not found");
        return data;
    }
    jstring result = (jstring) (*env)->CallStaticObjectMethod(env, utilClass, encodeMethod, data);
    return result;
}

static jstring c_dynamic1(JNIEnv *env, jobject thiz, jstring string) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return encode(env, string);
}

static jstring c_dynamic2(JNIEnv *env, jobject thiz, jstring string) {
    LOG("%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
    return encode(env, string);
}

static jstring c_dynamic3(JNIEnv *env, jclass clazz, jstring string) {
    LOG("%s(env=%p, clazz=%p)", __FUNCTION__, env, clazz);
    return encode(env, string);
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
            {"cDynamic1", "(Ljava/lang/String;)Ljava/lang/String;", (void *)&c_dynamic1},
            {"cDynamic2", "(Ljava/lang/String;)Ljava/lang/String;", (void *)&c_dynamic2},
            {"cDynamic3", "(Ljava/lang/String;)Ljava/lang/String;", (void *)&c_dynamic3},
    };
    jclass cls = (*env)->FindClass(env, "com/evilpan/demoapk/Facade");
    (*env)->RegisterNatives(env, cls, methods, sizeof(methods) / sizeof(methods[0]));
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
    jclass cls = (*env)->GetObjectClass(thiz, env);
    jmethodID callback = (*env)->GetStaticMethodID(env,
            cls, "static_callback", "(Ljava/lang/String;)V");
    jclass Context = (*env)->GetObjectClass(env, context);
    jmethodID method = (*env)->GetMethodID(env, Context, "getDataDir", "()Ljava/io/File;");
    jobject file = (*env)->CallObjectMethod(env, context, method);
    jstring ret = (jstring) (*env)->CallObjectMethod(env,
            file,
            (*env)->GetMethodID(env,
                    (*env)->FindClass(env, "java/io/File"),
                    "getAbsolutePath",
                    "()Ljava/lang/String;"));
    (*env)->CallStaticVoidMethod(env, cls, callback, ret);
    return (*env)->GetStringUTFLength(env, ret);
}

JNIEXPORT void JNICALL
Java_com_evilpan_demoapk_FacadeC_testArray(JNIEnv *env, jobject thiz, jintArray input) {
    LOG( "%s(env=%p, this=%p)", __FUNCTION__, env, thiz);
}
