#pragma once

#include "polynomial.h"
#include <stdint.h>
#include <vector>

namespace fheprac
{
	class PolyMatrix
	{
	public:
		PolyMatrix();

		PolyMatrix(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value = 0);

		uint64_t get(const size_t row, const size_t col, const size_t index) const;

		Polynomial get(const size_t row, const size_t col) const;

		void set(const size_t row, const size_t col, const size_t index, const uint64_t value);

		void set(const size_t row, const size_t col, const Polynomial& poly);

		uint64_t row_size() const;

		uint64_t col_size() const;

		uint64_t poly_modulus_degree() const;

		uint64_t modulus() const;

		void assign(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const  uint64_t modulus, const uint64_t value = 0);

		void reset(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value = 0);

		void reset_unsafe(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value = 0);

		PolyMatrix t() const;

		PolyMatrix operator+(const PolyMatrix& other) const;

		void operator+=(const PolyMatrix& other);

		PolyMatrix operator-(const PolyMatrix& other) const;

		void operator-=(const PolyMatrix& other);

		PolyMatrix operator-() const;

		PolyMatrix operator*(const PolyMatrix& other) const;

		PolyMatrix operator*(const uint64_t& other) const;

		void operator*=(const PolyMatrix& other);

		void operator*=(const uint64_t& other);

	private:
		std::vector<std::vector<Polynomial>> elems_;

		uint64_t row_size_;

		uint64_t col_size_;

		uint64_t poly_modulus_degree_;

		uint64_t modulus_;
	};
}