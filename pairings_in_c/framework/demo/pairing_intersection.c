#include "pbc/pbc.h"
#include "types.h"
#include "bigint/bi.h"
#include "fp/fp.h"
#include "ec/ec.h"
#include "fp/fp12.h"
#include "util.h"
#include "rand.h"
#include "hash/hashing.h"
#include "gss/sdh_zk.h"
#include "bigint/bi.h"
#include "ibe/bbkem.h"
#include "gss/gss_hwang.h"
#include "hash/hash_function.h"

#include <string.h>

void test_corectness(bool &reply, string c, string s, bbkem_public params, bbkem_public upsk) {
	
	repyl = true;
	ecfp_encoding ec1, ec2;
        ecfp_pow(&ec1, &s, params.k1);
	ecfp2_pow(&ec2, &c, params.k2);
	
	for(int i = 0; i < ec1.size(); i++){
		if(ec[i] != (ec1[i] & ec2[i]))){
			reply = false;
			break;
		}
	}
 }

int main(int argc, char *argv[]) {
	fp12_t res1, res2;
	ecpoint_fp  p;
	ecpoint_fp2 q;
	bigint_t k1, k2;
	
	// Generating parameters for the intersection.

	do {
		cprng_get_bytes(k1, BI_BYTES); fp_rdc_n(k1);
	} while (bi_compare(k1, bi_zero) == 0);
	do {
		cprng_get_bytes(k2, BI_BYTES); fp_rdc_n(k2);
	} while (bi_compare(k2, bi_zero) == 0);

	pbc_map_opt_ate(res1, &ECFP_GENERATOR, &ECFP2_GENERATOR);
	fp12_exp_cyclotomic(res2, (const fp4_t*)res1, k1);
	fp12_exp_cyclotomic(res1, (const fp4_t*)res2, k2);

	ecfp_mul(&p, &ECFP_GENERATOR, k1);
	ecfp2_mul(&q, &ECFP2_GENERATOR, k2);
	pbc_map_opt_ate(res2, &p, &q);

	PRINT_GT("res1: ", res1);
	PRINT_GT("res2: ", res2);

	hwang_signing_key sk;
  	hwang_public_parameters parameters;
  	hwang_signature sig;

  	hwang_init_parameters(&parameters);

  	hwang_generate_usk(&sk, &parameters);

  	hwang_sign(&sig, &parameters, &sk);

  	if (hwang_verify(&parameters, &sig) != 1)
    	print("Private Set Intersection Parameters Invalid");
  	else
    	print("Private Set Intersection Parameters is VALID!\n");

	byte key1[16], key2[16];
	bbkem_ciphertext ct;
	bbkem_public params;
	bbkem_msk msk;
	bbkem_pk upk;
	const char *id = "Bob";

	cprng_get_bytes(key1, 16);

	generate_params(&msk, &params);

	print("Generating parameters...\n");

	derive_private_key(&upk.d0, &msk, &params, id, argv[1]);
	derive_private_key(&upk.d1, &msk, &params, id, argv[2]);
	
	//Generating keys for the intersection.
	
	print("Group Private Key: \n");
	PRINT_G2("d0: ", upk.d0);
	PRINT_G2("d1: ", upk.d1);

	encapsulate_key(key1, &ct, &params, id);

	print("Generated symmetric key: \n");
	print("k: "); print_bytes(key1, 16); print("\n");
	print("Ciphertext: \n");
	PRINT_G1("c0:", ct.c0);
	PRINT_G1("c1:", ct.c1);
	
	bool reply = false;
	// Performing intersection e(p, g^a) == e(q, g^b).
	test_correctness(reply, argv[1], argv[2], params, upk);
	if(reply){
		// Setting environment variables in case the elements are equal.
		setenv("_k", (decapsulate_key(key1, &ct, &params, &upk)));
		setenv("_j", (decapsulate_key(key2, &ct, &params, argv[1])));
		setenv("_k", (decapsulate_key(key2, &ct, &params, argv[2])));
	}
}
