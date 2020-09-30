ghidra:
	install -d ${HOME}/ghidra_scripts/data
	install -m 644 ghidra/jni_helper.py ${HOME}/ghidra_scripts/
	install -m 644 headers/jni.h.gdt ${HOME}/ghidra_scripts/data/jni.h.gdt

ida:
	echo "TODO"

r2:
	echo "TODO"

.PHONY: ghidra
