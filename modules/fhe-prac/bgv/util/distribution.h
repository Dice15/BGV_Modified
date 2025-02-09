#pragma once

#include "../context.h"
#include "../encryptionparams.h"
#include "polynomial.h"
#include <stdint.h>

namespace fheprac
{
	Polynomial sample_poly_from_uniform_dist(const uint64_t poly_modulus_degree, const uint64_t modulus);

	Polynomial sample_poly_from_gaussian_dist(const uint64_t poly_modulus_degree, const uint64_t modulus);

	Polynomial sample_poly_from_hamming_dist(const uint64_t poly_modulus_degree, const uint64_t modulus);

	Polynomial sample_poly_from_zero_one_dist(const uint64_t poly_modulus_degree, const uint64_t modulus);
}