package com.evilpan;

import jadx.api.JavaMethod;
import jadx.core.dex.instructions.args.ArgType;

import java.util.ArrayList;

// https://edux.pjwstk.edu.pl/mat/268/lec/lect10/lecture10.html
public class MethodInfo {

    private String argumentSignature;
    private ArrayList<String> argumentTypes;
    private String returnType;
    private boolean isStatic;

    public MethodInfo(JavaMethod method) {
        argumentTypes = new ArrayList<>();
        StringBuilder argumentSignatureBuilder = new StringBuilder();
        for (ArgType argument : method.getArguments()) {
            argumentTypes.add(type2str(argument));
            argumentSignatureBuilder.append(type2sig(argument));
        }
        argumentSignature = argumentSignatureBuilder.toString();
        returnType = type2str(method.getReturnType());
        isStatic = method.getAccessFlags().isStatic();
    }

    public String getNativeName(String name, boolean isOverload) {
        name = name.replaceAll("_", "_1");
        name = mangleUnicode(name);
        name = name.replaceAll("\\.", "_");
        name = "Java_" + name;

		if (isOverload) {
            String sig = argumentSignature;
			sig = sig.replaceAll("_", "_1");
			sig = sig.replaceAll(";", "_2");
			sig = sig.replaceAll("\\[", "_3");
			sig = this.mangleUnicode(sig);
			sig = sig.replaceAll("/", "_");

			name = name + "__" + sig;
		}
        return name;
    }

	static String mangleUnicode(String s) {
		StringBuilder sb = new StringBuilder();

		for (int offset = 0; offset < s.length();) {
			int codepoint = s.codePointAt(offset);

			// If codepoint is ASCII:
			if (codepoint >= 0 && codepoint <= 127) {
				sb.append((char) codepoint);
			} else {
				// If unicode, convert e.g. character \u8c22 to _08c22
				sb.append("_0");
				sb.append(String.format("%4s", Integer.toHexString(codepoint)).replace(' ', '0'));
			}

			offset += Character.charCount(codepoint);
		}

		return sb.toString();
	}

    private static String type2str(ArgType tp) {
        String type;
        if (tp.isPrimitive()) {
            type = convertPrimitive(tp);
        } else if (tp.isArray()) {
            type = convertArray(tp);
        } else if (tp.toString().equals("java.lang.String")) {
            type = "jstring";
        } else {
            type = "jobject";
            // System.out.println("[-] treat " + tp.toString() + " as jobject");
        }
        return type;
    }

    private static String type2sig(ArgType argument) {
        String type;
        if (argument.isPrimitive()) {
            type = convertPrimitiveSignature(argument);
        } else if (argument.isArray()) {
            type = "[" + type2sig(argument.getArrayRootElement());
        } else {
            type = "L" + argument.getObject().replaceAll("\\.", "/") + ";";
        }
        return type;
    }

    private static String convertArray(ArgType type) {
        String ret;
        String name = type.getArrayRootElement().getPrimitiveType().getLongName();
        switch (name) {
            case "boolean":
            case "byte":
            case "char":
            case "int":
            case "short":
            case "long":
            case "float":
            case "double":
                ret = "j" + name + "Array";
                break;
            default:
                ret = "jobjectArray";
                break;
        }
        return ret;
    }

    private static String convertPrimitive(ArgType type) {
        String ret;
        String name = type.getPrimitiveType().getLongName();

        switch (name) {
            case "boolean":
            case "byte":
            case "char":
            case "short":
            case "int":
            case "long":
            case "float":
            case "double":
                ret = "j" + name;
                break;
            case "void":
                ret = "void";
                break;
            default:
                ret = null;
                break;
        }
        return ret;
    }

    private static String convertPrimitiveSignature(ArgType type) {
        String ret;
        switch (type.getPrimitiveType().getLongName()) {
            case "boolean":
                ret = "Z";
                break;
            case "byte":
                ret = "B";
                break;
            case "char":
                ret = "C";
                break;
            case "short":
                ret = "S";
                break;
            case "int":
                ret = "I";
                break;
            case "long":
                ret = "J";
                break;
            case "float":
                ret = "F";
                break;
            case "double":
                ret = "D";
                break;
            case "void":
                ret = "V";
                break;
            default:
                ret = null;
                break;
        }
        return ret;
    }
}
