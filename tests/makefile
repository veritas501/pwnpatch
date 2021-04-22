all:
	rm -f example_*
	gcc example.c -o example_64_pie -pie
	gcc example.c -o example_64_nopie -no-pie
	gcc example.c -o example_32_pie -pie -m32
	gcc example.c -o example_32_nopie -no-pie -m32
	gcc example.c -o example_64_static -static
	aarch64-linux-gnu-gcc example.c -o example_aarch64_static -static
	x86_64-w64-mingw32-gcc example.c -o example_mingw64