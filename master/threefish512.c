/*
	Threefish512 block cipher kernel module.
	threefish_encrypt_512 / threefish_decrypt_512 are based on 
	skein hash staging driver.
	Tweak is hardcoded to 0.
	
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/bitops.h>

#define  SKEIN_MAX_STATE_WORDS (8)  // orignially was 16, but that's useful only if we implement threefish1024
#define KeyScheduleConst 0x1BD11BDAA9FC1A22ULL
#define b64c64(X) le64_to_cpu(X)

struct threefish_key {
	//u64 state_size;
	u64 key[SKEIN_MAX_STATE_WORDS+1];   /* max number of key words*/
	//u64 tweak[3];
};

static void threefishSetKey512(struct threefish_key* keyCtx, u64* keyData)
{
    int i;
    u64 parity = KeyScheduleConst;

    for (i = 0; i != (512/64); ++i) {
        keyCtx->key[i] = b64c64(keyData[i]);
        parity ^= b64c64(keyData[i]);
    }
    keyCtx->key[i] = parity;
}

#define t0 0
#define t1 0
#define t2 0
void threefish_encrypt_512(const struct threefish_key *key_ctx, const u64 *input,
			   u64 *output)
{
	u64 b0 = b64c64(input[0]), b1 = b64c64(input[1]),
	    b2 = b64c64(input[2]), b3 = b64c64(input[3]),
	    b4 = b64c64(input[4]), b5 = b64c64(input[5]),
	    b6 = b64c64(input[6]), b7 = b64c64(input[7]);
	u64 k0 = key_ctx->key[0], k1 = key_ctx->key[1],
	    k2 = key_ctx->key[2], k3 = key_ctx->key[3],
	    k4 = key_ctx->key[4], k5 = key_ctx->key[5],
	    k6 = key_ctx->key[6], k7 = key_ctx->key[7],
	    k8 = key_ctx->key[8];
	//u64 t0 = key_ctx->tweak[0], t1 = key_ctx->tweak[1],
	//    t2 = key_ctx->tweak[2];

	b1 += k1;
	b0 += b1 + k0;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k3;
	b2 += b3 + k2;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k5 + t0;
	b4 += b5 + k4;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k7;
	b6 += b7 + k6 + t1;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k2;
	b0 += b1 + k1;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k4;
	b2 += b3 + k3;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k6 + t1;
	b4 += b5 + k5;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k8 + 1;
	b6 += b7 + k7 + t2;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k3;
	b0 += b1 + k2;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k5;
	b2 += b3 + k4;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k7 + t2;
	b4 += b5 + k6;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k0 + 2;
	b6 += b7 + k8 + t0;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k4;
	b0 += b1 + k3;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k6;
	b2 += b3 + k5;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k8 + t0;
	b4 += b5 + k7;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k1 + 3;
	b6 += b7 + k0 + t1;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k5;
	b0 += b1 + k4;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k7;
	b2 += b3 + k6;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k0 + t1;
	b4 += b5 + k8;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k2 + 4;
	b6 += b7 + k1 + t2;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k6;
	b0 += b1 + k5;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k8;
	b2 += b3 + k7;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k1 + t2;
	b4 += b5 + k0;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k3 + 5;
	b6 += b7 + k2 + t0;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k7;
	b0 += b1 + k6;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k0;
	b2 += b3 + k8;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k2 + t0;
	b4 += b5 + k1;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k4 + 6;
	b6 += b7 + k3 + t1;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k8;
	b0 += b1 + k7;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k1;
	b2 += b3 + k0;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k3 + t1;
	b4 += b5 + k2;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k5 + 7;
	b6 += b7 + k4 + t2;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k0;
	b0 += b1 + k8;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k2;
	b2 += b3 + k1;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k4 + t2;
	b4 += b5 + k3;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k6 + 8;
	b6 += b7 + k5 + t0;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k1;
	b0 += b1 + k0;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k3;
	b2 += b3 + k2;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k5 + t0;
	b4 += b5 + k4;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k7 + 9;
	b6 += b7 + k6 + t1;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k2;
	b0 += b1 + k1;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k4;
	b2 += b3 + k3;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k6 + t1;
	b4 += b5 + k5;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k8 + 10;
	b6 += b7 + k7 + t2;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k3;
	b0 += b1 + k2;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k5;
	b2 += b3 + k4;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k7 + t2;
	b4 += b5 + k6;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k0 + 11;
	b6 += b7 + k8 + t0;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k4;
	b0 += b1 + k3;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k6;
	b2 += b3 + k5;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k8 + t0;
	b4 += b5 + k7;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k1 + 12;
	b6 += b7 + k0 + t1;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k5;
	b0 += b1 + k4;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k7;
	b2 += b3 + k6;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k0 + t1;
	b4 += b5 + k8;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k2 + 13;
	b6 += b7 + k1 + t2;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k6;
	b0 += b1 + k5;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k8;
	b2 += b3 + k7;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k1 + t2;
	b4 += b5 + k0;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k3 + 14;
	b6 += b7 + k2 + t0;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k7;
	b0 += b1 + k6;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k0;
	b2 += b3 + k8;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k2 + t0;
	b4 += b5 + k1;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k4 + 15;
	b6 += b7 + k3 + t1;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	b1 += k8;
	b0 += b1 + k7;
	b1 = rol64(b1, 46) ^ b0;

	b3 += k1;
	b2 += b3 + k0;
	b3 = rol64(b3, 36) ^ b2;

	b5 += k3 + t1;
	b4 += b5 + k2;
	b5 = rol64(b5, 19) ^ b4;

	b7 += k5 + 16;
	b6 += b7 + k4 + t2;
	b7 = rol64(b7, 37) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 33) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 27) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 14) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 42) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 17) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 49) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 36) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 39) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 44) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 9) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 54) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 56) ^ b4;

	b1 += k0;
	b0 += b1 + k8;
	b1 = rol64(b1, 39) ^ b0;

	b3 += k2;
	b2 += b3 + k1;
	b3 = rol64(b3, 30) ^ b2;

	b5 += k4 + t2;
	b4 += b5 + k3;
	b5 = rol64(b5, 34) ^ b4;

	b7 += k6 + 17;
	b6 += b7 + k5 + t0;
	b7 = rol64(b7, 24) ^ b6;

	b2 += b1;
	b1 = rol64(b1, 13) ^ b2;

	b4 += b7;
	b7 = rol64(b7, 50) ^ b4;

	b6 += b5;
	b5 = rol64(b5, 10) ^ b6;

	b0 += b3;
	b3 = rol64(b3, 17) ^ b0;

	b4 += b1;
	b1 = rol64(b1, 25) ^ b4;

	b6 += b3;
	b3 = rol64(b3, 29) ^ b6;

	b0 += b5;
	b5 = rol64(b5, 39) ^ b0;

	b2 += b7;
	b7 = rol64(b7, 43) ^ b2;

	b6 += b1;
	b1 = rol64(b1, 8) ^ b6;

	b0 += b7;
	b7 = rol64(b7, 35) ^ b0;

	b2 += b5;
	b5 = rol64(b5, 56) ^ b2;

	b4 += b3;
	b3 = rol64(b3, 22) ^ b4;

	output[0] = b64c64(b0 + k0);
	output[1] = b64c64(b1 + k1);
	output[2] = b64c64(b2 + k2);
	output[3] = b64c64(b3 + k3);
	output[4] = b64c64(b4 + k4);
	output[5] = b64c64(b5 + k5 + t0);
	output[6] = b64c64(b6 + k6 + t1);
	output[7] = b64c64(b7 + k7 + 18);
}

void threefish_decrypt_512(const struct threefish_key *key_ctx, const u64 *input,
			   u64 *output)
{
	u64 b0 = b64c64(input[0]), b1 = b64c64(input[1]),
	    b2 = b64c64(input[2]), b3 = b64c64(input[3]),
	    b4 = b64c64(input[4]), b5 = b64c64(input[5]),
	    b6 = b64c64(input[6]), b7 = b64c64(input[7]);
	u64 k0 = key_ctx->key[0], k1 = key_ctx->key[1],
	    k2 = key_ctx->key[2], k3 = key_ctx->key[3],
	    k4 = key_ctx->key[4], k5 = key_ctx->key[5],
	    k6 = key_ctx->key[6], k7 = key_ctx->key[7],
	    k8 = key_ctx->key[8];
	//u64 t0 = key_ctx->tweak[0], t1 = key_ctx->tweak[1],
	//    t2 = key_ctx->tweak[2];

	u64 tmp;

	b0 -= k0;
	b1 -= k1;
	b2 -= k2;
	b3 -= k3;
	b4 -= k4;
	b5 -= k5 + t0;
	b6 -= k6 + t1;
	b7 -= k7 + 18;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k5 + t0;
	b7 -= k6 + 17;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k3;
	b5 -= k4 + t2;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k1;
	b3 -= k2;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k8;
	b1 -= k0;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k4 + t2;
	b7 -= k5 + 16;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k2;
	b5 -= k3 + t1;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k0;
	b3 -= k1;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k7;
	b1 -= k8;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k3 + t1;
	b7 -= k4 + 15;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k1;
	b5 -= k2 + t0;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k8;
	b3 -= k0;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k6;
	b1 -= k7;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k2 + t0;
	b7 -= k3 + 14;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k0;
	b5 -= k1 + t2;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k7;
	b3 -= k8;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k5;
	b1 -= k6;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k1 + t2;
	b7 -= k2 + 13;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k8;
	b5 -= k0 + t1;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k6;
	b3 -= k7;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k4;
	b1 -= k5;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k0 + t1;
	b7 -= k1 + 12;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k7;
	b5 -= k8 + t0;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k5;
	b3 -= k6;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k3;
	b1 -= k4;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k8 + t0;
	b7 -= k0 + 11;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k6;
	b5 -= k7 + t2;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k4;
	b3 -= k5;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k2;
	b1 -= k3;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k7 + t2;
	b7 -= k8 + 10;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k5;
	b5 -= k6 + t1;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k3;
	b3 -= k4;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k1;
	b1 -= k2;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k6 + t1;
	b7 -= k7 + 9;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k4;
	b5 -= k5 + t0;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k2;
	b3 -= k3;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k0;
	b1 -= k1;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k5 + t0;
	b7 -= k6 + 8;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k3;
	b5 -= k4 + t2;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k1;
	b3 -= k2;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k8;
	b1 -= k0;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k4 + t2;
	b7 -= k5 + 7;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k2;
	b5 -= k3 + t1;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k0;
	b3 -= k1;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k7;
	b1 -= k8;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k3 + t1;
	b7 -= k4 + 6;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k1;
	b5 -= k2 + t0;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k8;
	b3 -= k0;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k6;
	b1 -= k7;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k2 + t0;
	b7 -= k3 + 5;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k0;
	b5 -= k1 + t2;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k7;
	b3 -= k8;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k5;
	b1 -= k6;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k1 + t2;
	b7 -= k2 + 4;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k8;
	b5 -= k0 + t1;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k6;
	b3 -= k7;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k4;
	b1 -= k5;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k0 + t1;
	b7 -= k1 + 3;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k7;
	b5 -= k8 + t0;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k5;
	b3 -= k6;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k3;
	b1 -= k4;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k8 + t0;
	b7 -= k0 + 2;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k6;
	b5 -= k7 + t2;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k4;
	b3 -= k5;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k2;
	b1 -= k3;

	tmp = b3 ^ b4;
	b3 = (tmp >> 22) | (tmp << (64 - 22));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 56) | (tmp << (64 - 56));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 35) | (tmp << (64 - 35));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 8) | (tmp << (64 - 8));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 43) | (tmp << (64 - 43));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 29) | (tmp << (64 - 29));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 25) | (tmp << (64 - 25));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 17) | (tmp << (64 - 17));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 10) | (tmp << (64 - 10));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 50) | (tmp << (64 - 50));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 13) | (tmp << (64 - 13));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 24) | (tmp << (64 - 24));
	b6 -= b7 + k7 + t2;
	b7 -= k8 + 1;

	tmp = b5 ^ b4;
	b5 = (tmp >> 34) | (tmp << (64 - 34));
	b4 -= b5 + k5;
	b5 -= k6 + t1;

	tmp = b3 ^ b2;
	b3 = (tmp >> 30) | (tmp << (64 - 30));
	b2 -= b3 + k3;
	b3 -= k4;

	tmp = b1 ^ b0;
	b1 = (tmp >> 39) | (tmp << (64 - 39));
	b0 -= b1 + k1;
	b1 -= k2;

	tmp = b3 ^ b4;
	b3 = (tmp >> 56) | (tmp << (64 - 56));
	b4 -= b3;

	tmp = b5 ^ b2;
	b5 = (tmp >> 54) | (tmp << (64 - 54));
	b2 -= b5;

	tmp = b7 ^ b0;
	b7 = (tmp >> 9) | (tmp << (64 - 9));
	b0 -= b7;

	tmp = b1 ^ b6;
	b1 = (tmp >> 44) | (tmp << (64 - 44));
	b6 -= b1;

	tmp = b7 ^ b2;
	b7 = (tmp >> 39) | (tmp << (64 - 39));
	b2 -= b7;

	tmp = b5 ^ b0;
	b5 = (tmp >> 36) | (tmp << (64 - 36));
	b0 -= b5;

	tmp = b3 ^ b6;
	b3 = (tmp >> 49) | (tmp << (64 - 49));
	b6 -= b3;

	tmp = b1 ^ b4;
	b1 = (tmp >> 17) | (tmp << (64 - 17));
	b4 -= b1;

	tmp = b3 ^ b0;
	b3 = (tmp >> 42) | (tmp << (64 - 42));
	b0 -= b3;

	tmp = b5 ^ b6;
	b5 = (tmp >> 14) | (tmp << (64 - 14));
	b6 -= b5;

	tmp = b7 ^ b4;
	b7 = (tmp >> 27) | (tmp << (64 - 27));
	b4 -= b7;

	tmp = b1 ^ b2;
	b1 = (tmp >> 33) | (tmp << (64 - 33));
	b2 -= b1;

	tmp = b7 ^ b6;
	b7 = (tmp >> 37) | (tmp << (64 - 37));
	b6 -= b7 + k6 + t1;
	b7 -= k7;

	tmp = b5 ^ b4;
	b5 = (tmp >> 19) | (tmp << (64 - 19));
	b4 -= b5 + k4;
	b5 -= k5 + t0;

	tmp = b3 ^ b2;
	b3 = (tmp >> 36) | (tmp << (64 - 36));
	b2 -= b3 + k2;
	b3 -= k3;

	tmp = b1 ^ b0;
	b1 = (tmp >> 46) | (tmp << (64 - 46));
	b0 -= b1 + k0;
	b1 -= k1;

	output[0] = b64c64(b0);
	output[1] = b64c64(b1);
	output[2] = b64c64(b2);
	output[3] = b64c64(b3);

	output[7] = b64c64(b7);
	output[6] = b64c64(b6);
	output[5] = b64c64(b5);
	output[4] = b64c64(b4);
}


#undef t0
#undef t1
#undef t2


/* Encrypt one block.  in and out may be the same. */
static void cia_threefish512_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	threefish_encrypt_512((const struct threefish_key*)crypto_tfm_ctx(tfm), (const u64*)in, (u64*)out);
}

/* Decrypt one block.  in and out may be the same. */
static void cia_threefish512_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	threefish_decrypt_512((const struct threefish_key*)crypto_tfm_ctx(tfm), (const u64*)in, (u64*)out);
}

int cia_threefish512_setkey(struct crypto_tfm *tfm, const u8 *key, unsigned int key_len)
{
	threefishSetKey512((struct threefish_key*)crypto_tfm_ctx(tfm),(u64*)key);
	return 0;
}

static struct crypto_alg alg = {
	.cra_name           =   "threefish512",
	.cra_driver_name    =   "threefish512-generic",
	.cra_priority       =   100,
	.cra_flags          =   CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize      =   64,
	.cra_ctxsize        =   sizeof(struct threefish_key),
	.cra_alignmask      =	3,
	.cra_module         =   THIS_MODULE,
	.cra_u              =   { .cipher = {
	.cia_min_keysize    =   64,
	.cia_max_keysize    =   64,
	.cia_setkey         =   cia_threefish512_setkey,
	.cia_encrypt        =   cia_threefish512_encrypt,
	.cia_decrypt        =   cia_threefish512_decrypt } }
};

static int __init threefish_mod_init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit threefish_mod_fini(void)
{
	crypto_unregister_alg(&alg);
}

module_init(threefish_mod_init);
module_exit(threefish_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION ("Threefish512 Cipher Algorithm");
MODULE_ALIAS_CRYPTO("Threefish512");
MODULE_ALIAS_CRYPTO("threefish512-generic");
