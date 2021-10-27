/****************************************************************************
**
** Copyright (C) 2015 Stiftung Secure Information and
**                    Communication Technologies SIC and
**                    Graz University of Technology
** Contact: http://opensource.iaik.tugraz.at
**
**
** Commercial License Usage
** Licensees holding valid commercial licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and SIC. For further information
** contact us at http://opensource.iaik.tugraz.at.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
** This software is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this software. If not, see http://www.gnu.org/licenses/.
**
**
****************************************************************************/

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

int main(void) {
	fp12_t res1, res2;
	ecpoint_fp  p;
	ecpoint_fp2 q;
	bigint_t k1, k2;

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

	derive_private_key(&upk, &msk, &params, id);

	print("Group Private Key: \n");
	PRINT_G2("d0: ", upk.d0);
	PRINT_G2("d1: ", upk.d1);

	encapsulate_key(key1, &ct, &params, id);

	print("Generated symmetric key: \n");
	print("k: "); print_bytes(key1, 16); print("\n");
	print("Ciphertext: \n");
	PRINT_G1("c0:", ct.c0);
	PRINT_G1("c1:", ct.c1);

	decapsulate_key(key2, &ct, &params, &upk);
	print("Restored symmetric key: "); print_bytes(key2, 16); print("\n");
}
