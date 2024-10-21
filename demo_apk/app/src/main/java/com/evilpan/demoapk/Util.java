package com.evilpan.demoapk;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Util {
    public static String encode(String data) {
        byte[] out = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            out = Base64.getEncoder().encode(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(out);
        } else {
            return data;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = String.format("%02x", b);
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
