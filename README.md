# threefish_512
build it: make
load the module: insmod threefish512.ko

then create a LUKS container with cryptsetup in ECB and CTR modes
example:
cryptsetup luksFormat test -c threefish512-ctr-plain64 -s 512 -h sha512

key size must be 512!
I only implemented threefish512 since this seems to be the fastest on x86_64
It's 37% faster than serpent on my core2duo E8400

threefish256 might be faster on 32 bit cpus, but on such system you
would probably get more speed out of serpent sse2 implementation
