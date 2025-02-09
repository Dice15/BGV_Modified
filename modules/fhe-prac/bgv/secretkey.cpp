#include "secretkey.h"
#include <stdexcept>

namespace fheprac
{
	SecretKey::SecretKey(const size_t key_count)
	{
		assign(key_count);
	}

	void SecretKey::assign(const size_t key_count)
	{
		sk_.assign(key_count, std::vector<PolyMatrix>());

		for (auto& sk_l : sk_)
		{
			sk_l.assign(2, PolyMatrix());
		}
	}

	size_t SecretKey::count() const
	{
		return sk_.size();
	}

	const PolyMatrix& SecretKey::data(const size_t level, const size_t size) const
	{
		if (size < 2 || size > 3)
		{
			throw std::out_of_range("Ciphertext size must be either 2 or 3.");
		}

		return sk_[level][size - 2];
	}

	void SecretKey::data(const size_t level, const PolyMatrix& poly_matrix)
	{
		if (poly_matrix.row_size() < static_cast<size_t>(1))
		{
			throw std::invalid_argument("The polynomial matrix for the secret key must not be empty.");
		}

		if (poly_matrix.col_size() != static_cast<size_t>(1))
		{
			throw std::invalid_argument("The column size of the polynomial matrix for the secret key must be 1.");
		}

		sk_[level][0] = poly_matrix;
		tensor_square(poly_matrix, sk_[level][1]);
	}

	void SecretKey::tensor_square(const PolyMatrix& poly_matrix, PolyMatrix& destination) const
	{
		const Polynomial& sk_0 = poly_matrix.get(0, 0);
		const Polynomial& sk_1 = poly_matrix.get(1, 0);

		destination.assign(3, 1, poly_matrix.poly_modulus_degree(), poly_matrix.modulus());
		destination.set(0, 0, sk_0);
		destination.set(1, 0, sk_1);
		destination.set(2, 0, sk_1 * sk_1);
	}
}