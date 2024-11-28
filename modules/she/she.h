#pragma once

#include "seal/seal.h"
#include "common.h"
#include <vector>
#include <memory>


namespace she
{
    /**
    @class SHE
    A class implementing Somewhat Homomorphic Encryption (SHE) functionality using Microsoft SEAL.
    This class provides high-level APIs for encoding, decoding, encryption, decryption, and
    performing arithmetic operations on encrypted data.

    @details
    SHE encapsulates the following components:
    - SEALContext: Manages encryption parameters and their validation.
    - BatchEncoder: Encodes/decodes plaintexts for batching operations.
    - Encryptor: Encrypts plaintexts into ciphertexts.
    - Decryptor: Decrypts ciphertexts into plaintexts.
    - Evaluator: Performs arithmetic operations on ciphertexts.
    - Key management: Includes secret, public, relinearization, and Galois keys.
    */
    class SHE
    {
        /**
        Constructor for SHE.

        @param[in] context SEALContext managing encryption parameters.
        @param[in] encoder BatchEncoder for encoding/decoding.
        @param[in] encryptor Encryptor for encrypting plaintexts.
        @param[in] decryptor Decryptor for decrypting ciphertexts.
        @param[in] evaluator Evaluator for arithmetic operations.
        @param[in] default_mul_mode Default multiplication mode (element-wise or convolution).
        @param[in] secret_key Secret key for decryption.
        @param[in] public_key Public key for encryption.
        @param[in] relin_keys Relinearization keys for ciphertext operations.
        @param[in] galois_keys Galois keys for rotation operations.
        */
    public:
        SHE(
            std::unique_ptr<seal::SEALContext> context,
            std::unique_ptr<seal::BatchEncoder> encoder,
            std::unique_ptr<seal::Encryptor> encryptor,
            std::unique_ptr<seal::Decryptor> decryptor,
            std::unique_ptr<seal::Evaluator> evaluator,
            mul_mode_t default_mul_mode,
            const seal::SecretKey& secret_key,
            const seal::PublicKey& public_key,
            const seal::RelinKeys& relin_keys,
            const seal::GaloisKeys& galois_keys
        );

        // Plain modulus-related operations
        void plain_modulus_prime(uint64_t& destination) const;
        uint64_t plain_modulus_prime() const;
        void plain_modulus_primitive_root(const uint64_t n, uint64_t& destination) const;
        uint64_t plain_modulus_primitive_root(const uint64_t n) const;

        // Encoding operations
        void encode(const std::vector<int64_t>& vector, seal::Plaintext& destination, const mul_mode_t mul_mode) const;
        void encode(const std::vector<int64_t>& vector, seal::Plaintext& destination) const;
        seal::Plaintext encode(const std::vector<int64_t>& vector, const mul_mode_t mul_mode) const;
        seal::Plaintext encode(const std::vector<int64_t>& vector) const;

        // Decoding operations
        void decode(const seal::Plaintext& plaintext, std::vector<int64_t>& destination, const mul_mode_t mul_mode) const;
        void decode(const seal::Plaintext& plaintext, std::vector<int64_t>& destination) const;
        std::vector<int64_t> decode(const seal::Plaintext& plain, const mul_mode_t mul_mode) const;
        std::vector<int64_t> decode(const seal::Plaintext& plain) const;

        // Encryption operations
        void encrypt(const seal::Plaintext& plain, seal::Ciphertext& destination) const;
        seal::Ciphertext encrypt(const seal::Plaintext& plain) const;

        // Decryption operations
        void decrypt(const seal::Ciphertext& cipher, seal::Plaintext& destination) const;
        seal::Plaintext decrypt(const seal::Ciphertext& cipher) const;

        // Coefficient modulus matching
        bool mod_compare(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;
        void mod_matching(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination1, seal::Ciphertext& destination2) const;

        // Arithmetic operations: Addition
        void add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const;
        seal::Ciphertext add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;
        void add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const;
        seal::Ciphertext add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const;

        // Arithmetic operations: Subtraction
        void sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const;
        seal::Ciphertext sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;
        void sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const;
        seal::Ciphertext sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const;

        // Arithmetic operations: Multiplication
        void multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const;
        seal::Ciphertext multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const;
        void multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const;
        seal::Ciphertext multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const;

        // Negation
        void negate(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const;
        seal::Ciphertext negate(const seal::Ciphertext& ciphertext) const;

        // Rotations
        void rotate_rows(const seal::Ciphertext& ciphertext, const int step, seal::Ciphertext& destination) const;
        seal::Ciphertext rotate_rows(const seal::Ciphertext& ciphertext, const int step) const;
        void rotate_columns(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const;
        seal::Ciphertext rotate_columns(const seal::Ciphertext& ciphertext) const;

        // Slot-wise summation
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

        mul_mode_t default_mul_mode_;

        seal::SecretKey secret_key_;

        seal::PublicKey public_key_;

        seal::RelinKeys relin_keys_;

        seal::GaloisKeys galois_keys_;
    };
} // namespace she