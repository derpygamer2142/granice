build/main.bin: src/main.c include/compression_wrappers.h include/hashtable.h build/client.o build/http_wrapper.o
	gcc -o build/main.bin -I . \
	src/main.c build/client.o build/http_wrapper.o \
	-lssl -lz -lcrypto

build/client.o: src/client.c src/client.h
	gcc -c -o build/client.o -I . src/client.c -lssl -lcrypto

build/http_wrapper.o: src/http_wrapper.c src/http_wrapper.h
	gcc -c -o build/http_wrapper.o -I . src/http_wrapper.c -lssl -lcrypto

test build/test.bin: src/main.c include/compression_wrappers.h include/hashtable.h build/client.o build/http_wrapper.o
	rm -f build/*
	gcc -o build/main.bin -I . \
	src/main.c build/client.o build/http_wrapper.o \
	-lssl -lz -lcrypto -fsanitize=address

clean:
	rm -f build/*