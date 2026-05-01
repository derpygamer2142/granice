build/main.bin: src/main.c include/compression_wrappers.h include/hashtable.h
	rm -f build/*
	gcc -o build/main.bin -I . src/main.c -lssl -lz -lcrypto

test build/test.bin: src/main.c include/compression_wrappers.h include/hashtable.h
	rm -f build/*
	gcc -o build/test.bin -I . src/main.c -lssl -lz -lcrypto -fsanitize=address

clean:
	rm -f build/*