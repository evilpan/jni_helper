package com.evilpan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;

public class Main {

    public static void main(String[] args) {

        if (args.length != 2) {
            System.out.println("Usage: JadxFindJNI.jar <file.apk> <output.json>");
            return;
        }

        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setDebugInfo(false);
        jadxArgs.setSkipResources(true);
        jadxArgs.getInputFiles().add(new File(args[0]));
        JadxDecompiler jadx = new JadxDecompiler(jadxArgs);
        jadx.load();

        HashMap<String, ArrayList<MethodInfo>> methodInfos = new HashMap<>();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        for (JavaClass klass : jadx.getClasses()) {
            for (JavaMethod method : klass.getMethods()) {
                if (method.getAccessFlags().isNative()) {
                    String key = method.getFullName();
                    ArrayList<MethodInfo> overloadMethods = methodInfos.getOrDefault(key, null);
                    if (overloadMethods == null) {
                        overloadMethods = new ArrayList<>();
                        overloadMethods.add(new MethodInfo(method));
                        methodInfos.put(key, overloadMethods);
                    } else {
                        overloadMethods.add(new MethodInfo(method));
                        // methodInfos.put(key, overloadMethods);
                    }
                }
            }
        }
        // get formatted output
        HashMap<String, MethodInfo> result = new HashMap<>();
        Iterator it = methodInfos.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry e = (Map.Entry) it.next();
            String name = (String) e.getKey();
            ArrayList<MethodInfo> overloadMethods = (ArrayList<MethodInfo>) e.getValue();
            boolean isOverload = overloadMethods.size() > 1 ? true : false;
            for (MethodInfo m: overloadMethods) {
                String nativeName = m.getNativeName(name, isOverload);
                assert !result.containsKey(nativeName);
                result.put(nativeName, m);
            }
        }

        try {
            FileWriter outfile = new FileWriter(args[1]);
            outfile.append(gson.toJson(result));
            outfile.flush();
            outfile.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
