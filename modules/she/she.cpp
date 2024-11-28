#include "she.h"
#include <stdexcept>

namespace she
{
     /**
     * Initializes the Somewhat Homomorphic Encryption (SHE) object with provided SEAL components and keys.
     *
     * @param context The SEALContext, encapsulating encryption parameters and precomputations.
     * @param encoder The BatchEncoder for encoding/decoding plaintexts into batch matrices.
     * @param encryptor The Encryptor for encrypting plaintexts.
     * @param decryptor The Decryptor for decrypting ciphertexts.
     * @param evaluator The Evaluator for performing homomorphic operations.
     * @param default_mul_mode The default multiplication mode (element-wise or convolution).
     * @param secret_key The secret key for decryption and other operations.
     * @param public_key The public key for encryption.
     * @param relin_keys The relinearization keys for ciphertext multiplication.
     * @param galois_keys The Galois keys for rotation and batching operations.
     */
    SHE::SHE(
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
    )
        : context_(std::move(context)),
        encoder_(std::move(encoder)),
        encryptor_(std::move(encryptor)),
        decryptor_(std::move(decryptor)),
        evaluator_(std::move(evaluator)),
        default_mul_mode_(default_mul_mode),
        secret_key_(secret_key),
        public_key_(public_key),
        relin_keys_(relin_keys),
        galois_keys_(galois_keys) {
    }

    void SHE::plain_modulus_prime(uint64_t& destination) const {
        destination = context_->key_context_data()->parms().plain_modulus().value();
    }

    uint64_t SHE::plain_modulus_prime() const {
        uint64_t destination = -1;
        plain_modulus_prime(destination);
        return destination;
    }

    void SHE::plain_modulus_primitive_root(const uint64_t n, uint64_t& destination) const {
        if (!(n < 1 || (n & (n - 1)) != 0)) {
            seal::Modulus modulus = context_->key_context_data()->parms().plain_modulus();
            seal::util::try_primitive_root(n, modulus, destination);
        }
    }

    uint64_t SHE::plain_modulus_primitive_root(const uint64_t n) const {
        uint64_t destination = -1;
        plain_modulus_primitive_root(n, destination);
        return destination;
    }

    void SHE::encode(const std::vector<int64_t>& vector, seal::Plaintext& destination, const mul_mode_t mul_mode) const {
        encoder_->encode(vector, destination, static_cast<seal::mul_mode_type>(mul_mode));
    }

    void SHE::encode(const std::vector<int64_t>& vector, seal::Plaintext& destination) const {
        encode(vector, destination, default_mul_mode_);
    }

    seal::Plaintext SHE::encode(const std::vector<int64_t>& vector, const mul_mode_t mul_mode) const {
        seal::Plaintext destination;
        encode(vector, destination, mul_mode);
        return destination;
    }

    seal::Plaintext SHE::encode(const std::vector<int64_t>& vector) const {
        seal::Plaintext destination;
        encode(vector, destination);
        return destination;
    }

    void SHE::decode(const seal::Plaintext& plaintext, std::vector<int64_t>& destination, const mul_mode_t mul_mode) const {
        encoder_->decode(plaintext, destination, static_cast<seal::mul_mode_type>(mul_mode));
    }

    void SHE::decode(const seal::Plaintext& plaintext, std::vector<int64_t>& destination) const {
        decode(plaintext, destination, default_mul_mode_);
    }

    std::vector<int64_t> SHE::decode(const seal::Plaintext& plaintext, const mul_mode_t mul_mode) const {
        std::vector<int64_t> destination;
        decode(plaintext, destination, mul_mode);
        return destination;
    }

    std::vector<int64_t> SHE::decode(const seal::Plaintext& plaintext) const {
        std::vector<int64_t> destination;
        decode(plaintext, destination);
        return destination;
    }

    void SHE::encrypt(const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
        encryptor_->encrypt(plaintext, destination);
    }

    seal::Ciphertext SHE::encrypt(const seal::Plaintext& plaintext) const {
        seal::Ciphertext destination;
        encrypt(plaintext, destination);
        return destination;
    }

    void SHE::decrypt(const seal::Ciphertext& ciphertext, seal::Plaintext& destination) const {
        decryptor_->decrypt(ciphertext, destination);
    }

    seal::Plaintext SHE::decrypt(const seal::Ciphertext& ciphertext) const {
        seal::Plaintext destination;
        decrypt(ciphertext, destination);
        return destination;
    }

    bool SHE::mod_compare(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const {
        return ciphertext1.coeff_modulus_size() == ciphertext2.coeff_modulus_size();
    }

    void SHE::mod_matching(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination1, seal::Ciphertext& destination2) const {
        destination1 = ciphertext1;
        destination2 = ciphertext2;

        if (destination1.coeff_modulus_size() > destination2.coeff_modulus_size()) {
            std::swap(destination1, destination2);
        }

        while (destination1.coeff_modulus_size() < destination2.coeff_modulus_size()) {
            evaluator_->mod_switch_to_next_inplace(destination2);
        }
    }

    void SHE::add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const {

        auto add_cipher = [this](const seal::Ciphertext& cipher1, const seal::Ciphertext& cipher2, seal::Ciphertext& dest) {
            evaluator_->add(cipher1, cipher2, dest);
        };

        if (mod_compare(ciphertext1, ciphertext2)) {
            add_cipher(ciphertext1, ciphertext2, destination);
        }
        else {
            seal::Ciphertext cipher1;
            seal::Ciphertext cipher2;

            mod_matching(ciphertext1, ciphertext2, cipher1, cipher2);
            add_cipher(cipher1, cipher2, destination);
        }
    }

    seal::Ciphertext SHE::add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const {
        seal::Ciphertext destination;
        add(ciphertext1, ciphertext2, destination);
        return destination;
    }

    void SHE::add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
        evaluator_->add_plain(ciphertext, plaintext, destination);
    }

    seal::Ciphertext SHE::add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const {
        seal::Ciphertext destination;
        add(ciphertext, plaintext, destination);
        return destination;
    }

    void SHE::sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const {

        auto sub_cipher = [this](const seal::Ciphertext& cipher1, const seal::Ciphertext& cipher2, seal::Ciphertext& dest) {
            evaluator_->sub(cipher1, cipher2, dest);
        };

        if (mod_compare(ciphertext1, ciphertext2)) {
            sub_cipher(ciphertext1, ciphertext2, destination);
        }
        else {
            seal::Ciphertext cipher1;
            seal::Ciphertext cipher2;

            mod_matching(ciphertext1, ciphertext2, cipher1, cipher2);
            sub_cipher(cipher1, cipher2, destination);
        }
    }

    seal::Ciphertext SHE::sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const {
        seal::Ciphertext destination;
        sub(ciphertext1, ciphertext2, destination);
        return destination;
    }

    void SHE::sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
        evaluator_->sub_plain(ciphertext, plaintext, destination);
    }

    seal::Ciphertext SHE::sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const {
        seal::Ciphertext destination;
        sub(ciphertext, plaintext, destination);
        return destination;
    }

    void SHE::multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const {

        auto multiply_cipher = [this](const seal::Ciphertext& cipher1, const seal::Ciphertext& cipher2, seal::Ciphertext& dest) {
            evaluator_->multiply(cipher1, cipher2, dest);
            evaluator_->relinearize_inplace(dest, relin_keys_);

            if (dest.coeff_modulus_size() > 1) {
                evaluator_->mod_switch_to_next_inplace(dest);
            }
        };

        if (mod_compare(ciphertext1, ciphertext2)) {
            multiply_cipher(ciphertext1, ciphertext2, destination);
        }
        else {
            seal::Ciphertext cipher1;
            seal::Ciphertext cipher2;

            mod_matching(ciphertext1, ciphertext2, cipher1, cipher2);
            multiply_cipher(cipher1, cipher2, destination);
        }
    }

    seal::Ciphertext SHE::multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const {
        seal::Ciphertext destination;
        multiply(ciphertext1, ciphertext2, destination);
        return destination;
    }

    void SHE::multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
        evaluator_->multiply_plain(ciphertext, plaintext, destination);
        evaluator_->relinearize_inplace(destination, relin_keys_);

        if (destination.coeff_modulus_size() > 1) {
            evaluator_->mod_switch_to_next_inplace(destination);
        }
    }

    seal::Ciphertext SHE::multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const {
        seal::Ciphertext destination;
        multiply(ciphertext, plaintext, destination);
        return destination;
    }

    void SHE::negate(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const {
        evaluator_->negate(ciphertext, destination);
    }

    seal::Ciphertext SHE::negate(const seal::Ciphertext& ciphertext) const {
        seal::Ciphertext destination;
        negate(ciphertext, destination);
        return destination;
    }

    void SHE::rotate_rows(const seal::Ciphertext& ciphertext, const int32_t step, seal::Ciphertext& destination) const {
        evaluator_->rotate_rows(ciphertext, step, galois_keys_, destination);
    }

    seal::Ciphertext SHE::rotate_rows(const seal::Ciphertext& ciphertext, const int32_t step) const {
        seal::Ciphertext destination;
        rotate_rows(ciphertext, step, destination);
        return destination;
    }

    void SHE::rotate_columns(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const {
        evaluator_->rotate_columns(ciphertext, galois_keys_, destination);
    }

    seal::Ciphertext SHE::rotate_columns(const seal::Ciphertext& ciphertext) const {
        seal::Ciphertext destination;
        rotate_columns(ciphertext, destination);
        return destination;
    }

    void SHE::row_sum(const seal::Ciphertext& ciphertext, const int32_t range_size, seal::Ciphertext& destination) const {
        const int32_t half_slot_count = static_cast<int32_t>(encoder_->slot_count()) / 2;
        const int64_t logn = seal::util::get_power_of_two(static_cast<int64_t>(range_size));

        if (range_size < 2 || range_size > half_slot_count) {
            throw std::invalid_argument("The range size must be between 2 and the half slot count (inclusive).");
        }

        if (logn == -1) {
            throw std::invalid_argument("The range size must be a power of 2.");
        }

        destination = ciphertext;
        seal::Ciphertext rotated;

        for (int32_t i = 0, step = 1; i < logn; i++, step <<= 1) {
            rotate_rows(destination, step, rotated);
            add(destination, rotated, destination);
        }
    }

    seal::Ciphertext SHE::row_sum(const seal::Ciphertext& ciphertext, const int32_t range_size) const {
        seal::Ciphertext destination;
        row_sum(ciphertext, range_size, destination);
        return destination;
    }

    void SHE::column_sum(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const {
        seal::Ciphertext rotated;
        rotate_columns(ciphertext, rotated);
        add(ciphertext, rotated, destination);
    }

    seal::Ciphertext SHE::column_sum(const seal::Ciphertext& ciphertext) const {
        seal::Ciphertext destination;
        column_sum(ciphertext, destination);
        return destination;
    }
}