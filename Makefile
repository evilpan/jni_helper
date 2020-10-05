jni:
	make -C JadxFindJNI

demo:
	make -C demo

dist: jni
	zip JadxFindJNI.zip JadxFindJNI/JadxFindJNI.jar JadxFindJNI/lib/*.jar

clean:
	make -C JadxFindJNI clean
	make -C demo clean
	rm -rf JadxFindJNI.zip

.PHONY: jni demo clean dist
