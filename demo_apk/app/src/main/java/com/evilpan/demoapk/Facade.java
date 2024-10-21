package com.evilpan.demoapk;

public class Facade {

    private native String cDynamic1(String string);
    public native String cDynamic2(String string);
    public static native String cDynamic3(String string);

    private native String cppDynamic1(String string);
    public native String cppDynamic2(String string);
    public static native String cppDynamic3(String string);
}
