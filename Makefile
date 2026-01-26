build/main.bin: src/main.c
	rm -f build/*
	gcc -o build/main.bin -I . src/main.c -lssl -lz -lcrypto

clean:
	rm -f build/*