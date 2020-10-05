all: app-debug.json lib

lib: app-debug.apk
	unzip $^ "lib*"

JadxFindJNI:
	make -C ../JadxFindJNI

app-debug.json: app-debug.apk JadxFindJNI
	java -jar ../JadxFindJNI/JadxFindJNI.jar $< $@

clean: 
	rm -rf app-debug.json lib
	make -C ../JadxFindJNI clean

.PHONY: all lib clean JadxFindJNI
