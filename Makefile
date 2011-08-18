all:
	gcc -fPIC -gstabs+ -Wall -c arc4random.c
	gcc -fPIC -gstabs+ -Wall -c malloc.c
	gcc -shared -Wl,-soname,libobsdmalloc.so.1 -o libobsdmalloc.so.1 arc4random.o malloc.o -lc

clean:
	rm *.o *.so.1
