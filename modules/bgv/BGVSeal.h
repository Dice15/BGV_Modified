#pragma once

#include "seal/seal.h"
#include <vector>
#include <memory>

class SEALHelper
{
public:
    SEALHelper(
        std::unique_ptr<seal::SEALContext> context,
        std::unique_ptr<seal::BatchEncoder> encoder,
        std::unique_ptr<seal::Encryptor> encryptor,
        std::unique_ptr<seal::Decryptor> decryptor,
        std::unique_ptr<seal::Evaluator> evaluator,
        const seal::SecretKey& secret_key,
        const seal::PublicKey& public_key,
        const seal::RelinKeys& relin_keys,
        const seal::GaloisKeys& galois_keys
    );


    /*
    * plain modulus
    */
    void plain_modulus_prime(uint64_t& destination) const;

    uint64_t plain_modulus_prime() const;

    void plain_modulus_primitive_root(const uint64_t n, uint64_t& destination) const;

    uint64_t plain_modulus_primitive_root(const uint64_t n) const;


    /*
    * encode
    */
    void encode(const std::vector<int64_t>& vector, seal::Plaintext& destination) const;

    seal::Plaintext encode(const std::vector<int64_t>& vector) const;


    /*
    * decode
    */
    void decode(const seal::Plaintext& plaintext, std::vector<int64_t>& destination) const;

    std::vector<int64_t> decode(const seal::Plaintext& plain) const;


    /*
    * encrypt
    */
    void encrypt(const seal::Plaintext& plain, seal::Ciphertext& destination) const;

    seal::Ciphertext encrypt(const seal::Plaintext& plain) const;

    void encrypt(const std::vector<int64_t>& vector, seal::Ciphertext& destination) const;

    seal::Ciphertext encrypt(const std::vector<int64_t>& vector) const;


    /*
    * decrypt
    */
    void decrypt(const seal::Ciphertext& cipher, seal::Plaintext& destination) const;

    seal::Plaintext decrypt(const seal::Ciphertext& cipher) const;


    /*
    * coeff modulus
    */
    bool mod_compare(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;

    void mod_matching(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination1, seal::Ciphertext& destination2) const;


    /*
    * add
    */
    void add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const;

    seal::Ciphertext add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;

    void add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const;

    seal::Ciphertext add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const;

    void add(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector, seal::Ciphertext& destination) const;

    seal::Ciphertext add(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector) const;


    /*
    * sub
    */
    void sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const;

    seal::Ciphertext sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;

    void sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const;

    seal::Ciphertext sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const;

    void sub(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector, seal::Ciphertext& destination) const;

    seal::Ciphertext sub(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector) const;


    /*
    * multiply
    */
    void multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const;

    seal::Ciphertext multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;

    void multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const;

    seal::Ciphertext multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const;

    void multiply(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector, seal::Ciphertext& destination) const;

    seal::Ciphertext multiply(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector) const;


    /*
    * negate
    */
    void negate(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const;

    seal::Ciphertext negate(const seal::Ciphertext& ciphertext) const;


    /*
    * rotate_rows
    */
    void rotate_rows(const seal::Ciphertext& ciphertext, const int step, seal::Ciphertext& destination) const;

    seal::Ciphertext rotate_rows(const seal::Ciphertext& ciphertext, const int step) const;


    /*
    * rotate_columns
    */
    void rotate_columns(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const;

    seal::Ciphertext rotate_columns(const seal::Ciphertext& ciphertext) const;


    /*
    * slot sum
    */
    void row_sum(const seal::Ciphertext& ciphertext, const int32_t range_size, seal::Ciphertext& destination) const;

    seal::Ciphertext row_sum(const seal::Ciphertext& ciphertext, const int32_t range_size) const;

    void column_sum(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const;

    seal::Ciphertext column_sum(const seal::Ciphertext& ciphertext) const;


private:
    std::unique_ptr<seal::SEALContext> context_;

    std::unique_ptr<seal::BatchEncoder> encoder_;

    std::unique_ptr<seal::Encryptor> encryptor_;

    std::unique_ptr<seal::Decryptor> decryptor_;

    std::unique_ptr<seal::Evaluator> evaluator_;

    seal::SecretKey secret_key_;

    seal::PublicKey public_key_;

    seal::RelinKeys relin_keys_;

    seal::GaloisKeys galois_keys_;
};