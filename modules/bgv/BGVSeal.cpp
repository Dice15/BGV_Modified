// BGVSeal.cpp
#include "BGVSeal.h"
#include <stdexcept>

SEALHelper::SEALHelper(
    std::unique_ptr<seal::SEALContext> context,
    std::unique_ptr<seal::BatchEncoder> encoder,
    std::unique_ptr<seal::Encryptor> encryptor,
    std::unique_ptr<seal::Decryptor> decryptor,
    std::unique_ptr<seal::Evaluator> evaluator,
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
    secret_key_(secret_key),
    public_key_(public_key),
    relin_keys_(relin_keys),
    galois_keys_(galois_keys) {
}


/*
* plain modulus
*/
void SEALHelper::plain_modulus_prime(uint64_t& destination) const {
    destination = context_->key_context_data()->parms().plain_modulus().value();
}

uint64_t SEALHelper::plain_modulus_prime() const {
    uint64_t destination = -1;
    plain_modulus_prime(destination);
    return destination;
}

void SEALHelper::plain_modulus_primitive_root(const uint64_t n, uint64_t& destination) const {
    if (!(n < 1 || (n & (n - 1)) != 0)) {
        seal::Modulus modulus = context_->key_context_data()->parms().plain_modulus();
        seal::util::try_primitive_root(n, modulus, destination);
    }
}

uint64_t SEALHelper::plain_modulus_primitive_root(const uint64_t n) const {
    uint64_t destination = -1;
    plain_modulus_primitive_root(n, destination);
    return destination;
}


/*
* encode
*/
void SEALHelper::encode(const std::vector<int64_t>& vector, seal::Plaintext& destination) const {
    encoder_->encode(vector, destination);
}

seal::Plaintext SEALHelper::encode(const std::vector<int64_t>& vector) const {
    seal::Plaintext destination;
    encode(vector, destination);
    return destination;
}


/*
* decode
*/
void SEALHelper::decode(const seal::Plaintext& plaintext, std::vector<int64_t>& destination) const {
    encoder_->decode(plaintext, destination);
}

std::vector<int64_t> SEALHelper::decode(const seal::Plaintext& plaintext) const {
    std::vector<int64_t> destination;
    decode(plaintext, destination);
    return destination;
}


/*
* encrypt
*/
void SEALHelper::encrypt(const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
    encryptor_->encrypt(plaintext, destination);
}

seal::Ciphertext SEALHelper::encrypt(const seal::Plaintext& plaintext) const {
    seal::Ciphertext destination;
    encrypt(plaintext, destination);
    return destination;
}

void SEALHelper::encrypt(const std::vector<int64_t>& vector, seal::Ciphertext& destination) const {
    seal::Plaintext plaintext;
    encode(vector, plaintext);
    encryptor_->encrypt(plaintext, destination);
}

seal::Ciphertext SEALHelper::encrypt(const std::vector<int64_t>& vector) const {
    seal::Ciphertext destination;
    encrypt(vector, destination);
    return destination;
}


/*
* decrypt
*/
void SEALHelper::decrypt(const seal::Ciphertext& ciphertext, seal::Plaintext& destination) const {
    decryptor_->decrypt(ciphertext, destination);
}

seal::Plaintext SEALHelper::decrypt(const seal::Ciphertext& ciphertext) const {
    seal::Plaintext destination;
    decrypt(ciphertext, destination);
    return destination;
}


/*
* coeff modulus
*/
bool SEALHelper::mod_compare(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const {
    return ciphertext1.coeff_modulus_size() == ciphertext2.coeff_modulus_size();
}

void SEALHelper::mod_matching(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination1, seal::Ciphertext& destination2) const {
    destination1 = ciphertext1;
    destination2 = ciphertext2;

    if (destination1.coeff_modulus_size() > destination2.coeff_modulus_size()) {
        std::swap(destination1, destination2);
    }

    while (destination1.coeff_modulus_size() < destination2.coeff_modulus_size()) {
        evaluator_->mod_switch_to_next_inplace(destination2);
    }
}


/*
* add
*/
void SEALHelper::add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const {

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

seal::Ciphertext SEALHelper::add(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const  {
    seal::Ciphertext destination;
    add(ciphertext1, ciphertext2, destination);
    return destination;
}

void SEALHelper::add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
    evaluator_->add_plain(ciphertext, plaintext, destination);
}

seal::Ciphertext SEALHelper::add(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const {
    seal::Ciphertext destination;
    add(ciphertext, plaintext, destination);
    return destination;
}

void SEALHelper::add(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector, seal::Ciphertext& destination) const {
    seal::Plaintext plaintext;
    encode(vector, plaintext);
    add(ciphertext, plaintext, destination);
}

seal::Ciphertext SEALHelper::add(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector) const {
    seal::Ciphertext destination;
    add(ciphertext, vector, destination);
    return destination;
}


/*
* sub
*/
void SEALHelper::sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const {

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

seal::Ciphertext SEALHelper::sub(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const {
    seal::Ciphertext destination;
    sub(ciphertext1, ciphertext2, destination);
    return destination;
}

void SEALHelper::sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
    evaluator_->sub_plain(ciphertext, plaintext, destination);
}

seal::Ciphertext SEALHelper::sub(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const {
    seal::Ciphertext destination;
    sub(ciphertext, plaintext, destination);
    return destination;
}

void SEALHelper::sub(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector, seal::Ciphertext& destination) const {
    seal::Plaintext plaintext;
    encode(vector, plaintext);
    sub(ciphertext, plaintext, destination);
}

seal::Ciphertext SEALHelper::sub(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector) const {
    seal::Ciphertext destination;
    sub(ciphertext, vector, destination);
    return destination;
}


/*
* multiply
*/
void SEALHelper::multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2, seal::Ciphertext& destination) const {

    auto multiply_cipher = [this](const seal::Ciphertext& cipher1, const seal::Ciphertext& cipher2, seal::Ciphertext& dest) {
        evaluator_->multiply(cipher1, cipher2, dest);
        evaluator_->relinearize_inplace(dest, relin_keys_);

        if (context_->last_parms_id() != dest.parms_id()) {
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

seal::Ciphertext SEALHelper::multiply(const seal::Ciphertext& ciphertext1, const seal::Ciphertext& ciphertext2) const {
    seal::Ciphertext destination;
    multiply(ciphertext1, ciphertext2, destination);
    return destination;
}

void SEALHelper::multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext, seal::Ciphertext& destination) const {
    evaluator_->multiply_plain(ciphertext, plaintext, destination);
    evaluator_->relinearize_inplace(destination, relin_keys_);

    if (context_->last_parms_id() != destination.parms_id()) {
        evaluator_->mod_switch_to_next_inplace(destination);
    }
}

seal::Ciphertext SEALHelper::multiply(const seal::Ciphertext& ciphertext, const seal::Plaintext& plaintext) const {
    seal::Ciphertext destination;
    multiply(ciphertext, plaintext, destination);
    return destination;
}

void SEALHelper::multiply(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector, seal::Ciphertext& destination) const {
    seal::Plaintext plaintext;
    encode(vector, plaintext);

    evaluator_->multiply_plain(ciphertext, plaintext, destination);
    evaluator_->relinearize_inplace(destination, relin_keys_);

    if (context_->last_parms_id() != destination.parms_id()) {
        evaluator_->mod_switch_to_next_inplace(destination);
    }
}

seal::Ciphertext SEALHelper::multiply(const seal::Ciphertext& ciphertext, const std::vector<int64_t>& vector) const {
    seal::Ciphertext destination;
    multiply(ciphertext, vector, destination);
    return destination;
}


/*
* negate
*/
void SEALHelper::negate(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const {
    evaluator_->negate(ciphertext, destination);
}

seal::Ciphertext SEALHelper::negate(const seal::Ciphertext& ciphertext) const {
    seal::Ciphertext destination;
    negate(ciphertext, destination);
    return destination;
}


/*
* roate_rows
*/
void SEALHelper::rotate_rows(const seal::Ciphertext& ciphertext, const int32_t step, seal::Ciphertext& destination) const {
    evaluator_->rotate_rows(ciphertext, step, galois_keys_, destination);
}

seal::Ciphertext SEALHelper::rotate_rows(const seal::Ciphertext& ciphertext, const int32_t step) const {
    seal::Ciphertext destination;
    rotate_rows(ciphertext, step,destination);
    return destination;
}


/*
* rotate_columns
*/
void SEALHelper::rotate_columns(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const {
    evaluator_->rotate_columns(ciphertext, galois_keys_, destination);
}

seal::Ciphertext SEALHelper::rotate_columns(const seal::Ciphertext& ciphertext) const {
    seal::Ciphertext destination;
    rotate_columns(ciphertext, destination);
    return destination;
}


/*
* slot sum
*/
void SEALHelper::row_sum(const seal::Ciphertext& ciphertext, const int32_t range_size, seal::Ciphertext& destination) const {
    const int32_t half_slot_count = encoder_->slot_count() / 2;
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

seal::Ciphertext SEALHelper::row_sum(const seal::Ciphertext& ciphertext, const int32_t range_size) const {
    seal::Ciphertext destination;
    row_sum(ciphertext, range_size, destination);
    return destination;
}

void SEALHelper::column_sum(const seal::Ciphertext& ciphertext, seal::Ciphertext& destination) const {
    seal::Ciphertext rotated;
    rotate_columns(ciphertext, rotated);
    add(ciphertext, rotated, destination);
}

seal::Ciphertext SEALHelper::column_sum(const seal::Ciphertext& ciphertext) const {
    seal::Ciphertext destination;
    column_sum(ciphertext, destination);
    return destination;
}