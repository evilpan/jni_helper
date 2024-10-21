package com.evilpan.demoapk;

import android.content.Context;
import android.util.Log;

public class FacadeCpp {
    static {
        System.loadLibrary("democpp");
    }

    private void callback(String data) {
        Log.i("JNIDemo", "callback with data: " + data);
    }

    private static void static_callback(String data) {
        Log.i("JNIDemo", "static callback with data: " + data);
    }

    public native String stringFromJNI();
    public native int testOverload();
    public native int testOverload(int i);
    public native int testOverload(long i, float j, double k);
    public static native int testStatic(int i);
    public native int testClass(Context context);
    public native void testArray(int[] input);
}
