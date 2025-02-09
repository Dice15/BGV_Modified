#include "polymatrix.h"
#include <stdexcept>
#include <iostream>

namespace fheprac
{
    PolyMatrix::PolyMatrix() : row_size_(0), col_size_(0), poly_modulus_degree_(0), modulus_(0) {}

    PolyMatrix::PolyMatrix(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
        : row_size_(row_size), col_size_(col_size), poly_modulus_degree_(poly_modulus_degree), modulus_(modulus)
    {
        elems_.assign(row_size_, std::vector<Polynomial>(col_size_));

        for (size_t r = 0; r < row_size_; r++)
        {
            for (size_t c = 0; c < col_size_; c++)
            {
                elems_[r][c].assign(poly_modulus_degree_, modulus_, value);
            }
        }
    }

    uint64_t PolyMatrix::get(const size_t row, const size_t col, const size_t index) const
    {
        if (row >= row_size_ || col >= col_size_)
        {
            throw std::out_of_range("Row/Col out of range.");
        }

        return elems_[row][col].get(index);
    }

    Polynomial PolyMatrix::get(const size_t row, const size_t col) const
    {
        if (row >= row_size_ || col >= col_size_)
        {
            throw std::out_of_range("Row/Col out of range.");
        }

        return elems_[row][col];
    }

    void PolyMatrix::set(const size_t row, const size_t col, const size_t index, const uint64_t value)
    {
        if (row >= row_size_ || col >= col_size_)
        {
            throw std::out_of_range("Row/Col out of range.");
        }

        elems_[row][col].set(index, value);
    }

    void PolyMatrix::set(const size_t row, const size_t col, const Polynomial& poly)
    {
        for (size_t i = 0; i < poly.poly_modulus_degree(); i++)
        {
            set(row, col, i, poly.get(i));
        }
    }

    uint64_t PolyMatrix::row_size() const
    {
        return row_size_;
    }

    uint64_t PolyMatrix::col_size() const
    {
        return col_size_;
    }

    uint64_t PolyMatrix::poly_modulus_degree() const
    {
        return poly_modulus_degree_;
    }

    uint64_t PolyMatrix::modulus() const
    {
        return modulus_;
    }

    void PolyMatrix::assign(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
    {
        row_size_ = row_size;
        col_size_ = col_size;
        poly_modulus_degree_ = poly_modulus_degree;
        modulus_ = modulus;
        elems_.assign(row_size_, std::vector<Polynomial>(col_size_));

        for (size_t r = 0; r < row_size_; r++)
        {
            for (size_t c = 0; c < col_size_; c++)
            {
                elems_[r][c].assign(poly_modulus_degree_, modulus_, value);
            }
        }
    }

    void PolyMatrix::reset(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
    {
        row_size_ = row_size;
        col_size_ = col_size;
        poly_modulus_degree_ = poly_modulus_degree;
        modulus_ = modulus;
        elems_.resize(row_size_);

        for (size_t r = 0; r < row_size_; r++)
        {
            elems_[r].resize(col_size_);

            for (size_t c = 0; c < col_size_; c++)
            {
                elems_[r][c].reset(poly_modulus_degree_, modulus_, value);
            }
        }
    }

    void PolyMatrix::reset_unsafe(const size_t row_size, const size_t col_size, const uint64_t poly_modulus_degree, const uint64_t modulus, const uint64_t value)
    {
        row_size_ = row_size;
        col_size_ = col_size;
        poly_modulus_degree_ = poly_modulus_degree;
        modulus_ = modulus;
        elems_.resize(row_size_);

        for (size_t r = 0; r < row_size_; r++)
        {
            elems_[r].resize(col_size_);

            for (size_t c = 0; c < col_size_; c++)
            {
                elems_[r][c].reset_unsafe(poly_modulus_degree_, modulus_, value);
            }
        }
    }

    PolyMatrix PolyMatrix::t() const
    {
        PolyMatrix destination(col_size_, row_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                destination.elems_[c][r] = elems_[r][c];
            }
        }

        return destination;
    }

    PolyMatrix PolyMatrix::operator+(const PolyMatrix& other) const
    {
        if (row_size_ != other.row_size_ || col_size_ != other.col_size_ || poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
        {
            throw std::invalid_argument("PolyMatrixs must have matching dimension, degree and modulus.");
        }

        PolyMatrix destination(row_size_, col_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                destination.elems_[r][c] = elems_[r][c] + other.elems_[r][c];
            }
        }

        return destination;
    }

    void PolyMatrix::operator+=(const PolyMatrix& other)
    {
        if (row_size_ != other.row_size_ || col_size_ != other.col_size_ || poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
        {
            throw std::invalid_argument("PolyMatrixs must have matching dimension, degree and modulus.");
        }

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                elems_[r][c] += other.elems_[r][c];
            }
        }
    }

    PolyMatrix PolyMatrix::operator-(const PolyMatrix& other) const
    {
        if (row_size_ != other.row_size_ || col_size_ != other.col_size_ || poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
        {
            throw std::invalid_argument("PolyMatrixs must have matching dimension, degree and modulus.");
        }

        PolyMatrix destination(row_size_, col_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                destination.elems_[r][c] = elems_[r][c] - other.elems_[r][c];
            }
        }

        return destination;
    }

    void PolyMatrix::operator-=(const PolyMatrix& other)
    {
        if (row_size_ != other.row_size_ || col_size_ != other.col_size_ || poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
        {
            throw std::invalid_argument("PolyMatrixs must have matching dimension, degree and modulus.");
        }

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                elems_[r][c] -= other.elems_[r][c];
            }
        }
    }

    PolyMatrix PolyMatrix::operator-() const
    {
        PolyMatrix destination(row_size_, col_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                destination.elems_[r][c] = -(elems_[r][c]);
            }
        }

        return destination;
    }


    PolyMatrix PolyMatrix::operator*(const PolyMatrix& other) const
    {
        if (col_size_ != other.row_size_)
        {
            throw std::invalid_argument("PolyMatrixs must have matching dimension.");
        }

        if (poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
        {
            throw std::invalid_argument("PolyMatrixs must have matching degree and modulus.");
        }

        PolyMatrix destination(row_size_, other.col_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < other.col_size_; c++)
            {
                for (uint64_t i = 0; i < col_size_; i++)
                {
                    destination.elems_[r][c] += (elems_[r][i] * other.elems_[i][c]);
                }
            }
        }

        return destination;
    }

    PolyMatrix PolyMatrix::operator*(const uint64_t& other) const
    {
        PolyMatrix destination(row_size_, col_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                destination.elems_[r][c] = elems_[r][c] * other;
            }
        }

        return destination;
    }

    void PolyMatrix::operator*=(const PolyMatrix& other)
    {
        if (row_size_ != other.row_size_ || col_size_ != other.col_size_ || poly_modulus_degree_ != other.poly_modulus_degree_ || modulus_ != other.modulus_)
        {
            throw std::invalid_argument("PolyMatrixs must have matching dimension, degree and modulus.");
        }

        PolyMatrix destination(row_size_, other.col_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < other.col_size_; c++)
            {
                for (uint64_t i = 0; i < col_size_; i++)
                {
                    destination.elems_[r][c] += (elems_[r][i] * other.elems_[i][c]);
                }
            }
        }

        assign(row_size_, other.col_size_, poly_modulus_degree_, modulus_);

        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < other.col_size_; c++)
            {
                elems_[r][c] = destination.elems_[r][c];
            }
        }
    }

    void PolyMatrix::operator*=(const uint64_t& other)
    {
        for (uint64_t r = 0; r < row_size_; r++)
        {
            for (uint64_t c = 0; c < col_size_; c++)
            {
                elems_[r][c] = elems_[r][c] * other;
            }
        }
    }
}