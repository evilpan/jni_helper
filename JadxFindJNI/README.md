# JadxFindJNI

Find JNI functions from apk and export to JSON file.

## Build

```sh
$ make
```

## Usage

```
$ java -jar JadxFindJNI.jar
Usage: JadxFindJNI.jar <file.apk> <output.json>
```

## Update Jadx (Optional)

```sh
# 1. download latest release from https://github.com/skylot/jadx/releases
wget https://github.com/skylot/jadx/releases/download/v1.1.0/jadx-1.1.0.zip -O jdax.zip

# 2. unzip libraries 
rm -rf lib && unzip jadx.zip "lib/*"

# 3. update dependencies in
- Makefile
- src/META-INF/MANIFEST.MF
```

## Credits

- [skylot/jadx][jadx]
- [Ayrx/FindNativeJNIMethods][ayrx]

[jadx]: https://github.com/skylot/jadx
[ayrx]: https://github.com/Ayrx/FindNativeJNIMethods
