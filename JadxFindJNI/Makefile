all: JadxFindJNI.jar

out: src/com/evilpan/Main.java
	mkdir $@
	javac -classpath lib/gson-2.8.6.jar:lib/jadx-core-1.1.0.jar -sourcepath src -d $@ $<

JadxFindJNI.jar: out
	jar -cvfm $@ src/META-INF/MANIFEST.MF  -C $^/ .

clean:
	rm -rf out JadxFindJNI.jar

.PHONEY: all out clean
