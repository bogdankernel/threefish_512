# threefish_512 v0.2

* changed cipher name to threefish (only 512 keysize implemented still)
* fixed some a possible big-endian bug. I don't have a BE system to test

* Added tweak operating mode.
THIS IS EXPERIMENTAL, my code is based on kernel-hacking guesswork.
Seems to be working though :)

tweak mode example:
cryptsetup luksFormat test -c threefish-tweak-plain64 -s 512

It's about 7% faster than ctr mode and same speed as ecb, but more
secure. threefish doesn't need xts or ctr, as it has built in tweak. 

I only use the first 64 bits of the tweak. I don't think cryptsetup
provides 128 tweak. But can be easily changed to support it, if there's
anything that can use it.


# threefish_512 v0.1 features

build it: make

load the module: insmod threefish512.ko

then create a LUKS container with cryptsetup in ECB, CBC and CTR modes        
example:           
cryptsetup luksFormat test -c threefish-ctr-plain64 -s 512

key size must be 512!
I only implemented threefish512 since this seems to be the fastest on x86_64
It's 37% faster than serpent on my core2duo E8400

threefish256 might be faster on 32 bit cpus, but on such system you
would probably get more speed out of serpent sse2 implementation
