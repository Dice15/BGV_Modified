#include "seal/seal.h"
#include "patternmatch.h"
#include "../she/shebuilder.h"
#include "../she/she.h"
#include "../random/RandomGenerator.h"
#include <openssl/sha.h>
#include <complex>
#include <stdexcept>
#include <unordered_map>
#include <chrono>

std::pair<std::vector<int64_t>, std::vector<int64_t>> PatternMatch::convert_integer_data(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern) 
{
    std::unordered_map<int16_t, int64_t> mapping;
    int32_t next_value = 0;

    auto build_map = [&mapping, &next_value](const std::vector<int16_t>& data) 
    {
        for (auto e : data) 
        {
            if (mapping.find(e) == mapping.end()) 
            {
                mapping.insert({ e, next_value++ });
            }
        }
    };

    auto convert = [&mapping](const std::vector<int16_t>& integer_data) 
    {
        std::vector<int64_t> new_data;

        new_data.reserve(integer_data.size());

        for (auto e : integer_data) 
        {
            new_data.push_back(mapping.at(e));
        }

        return new_data;
    };

    build_map(text);
    build_map(pattern);

    return { convert(text), convert(pattern) };
}

std::pair<double, std::vector<int64_t>> PatternMatch::integer_matching(const std::vector<int16_t>& text, const std::vector<int16_t>& pattern, const integer_matching_type matching_type)
{
    auto [new_text, new_pattern] = convert_integer_data(text, pattern);
    std::vector<int64_t> matched;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    switch (matching_type)
    {
    case integer_matching_type::hash_rotation_in_bgv: {
        integer_hash_rotation(new_text, new_pattern, matched);
        break;
    }
    case integer_matching_type::hash_primitive_root_in_bgv : {
        integer_hash_primitive_root_in_bgv(new_text, new_pattern, matched);
        break;
    }
    case integer_matching_type::hash_primitive_root_in_ckks: {
        integer_hash_primitive_root_in_ckks(new_text, new_pattern, matched);
        break;
    }                                                         
    default:
        throw std::invalid_argument("Unsupported matching type");
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    return { elapsed.count(), matched };
}

std::string PatternMatch::sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void PatternMatch::integer_hash_rotation(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int64_t>& matched) {
    // random module
    RandomGenerator rand;


    // create bgv
    she::SHE& bgv = she::SHEBuilder()
        .sec_level(she::sec_level_t::tc128)
        .mul_mode(she::mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(she::int_scheme_t::bgv, static_cast<size_t>(pow(2, 14)), 30, { 60, 60, 60, 60 ,60 });


    // get plain modulus prime
    int64_t prime = bgv.plain_modulus_prime();


    // create Bob function
    auto bob = [&](seal::Ciphertext& pattern_enc, int32_t pattern_size) 
    {
        std::vector<int64_t> text_sav(text);
        std::vector<std::vector<seal::Ciphertext>> result_e(pattern_size, std::vector<seal::Ciphertext>(2));
        std::vector<std::vector<std::string>> hash(pattern_size, std::vector<std::string>(text.size(), ""));

        for (int64_t rot = 0; rot < pattern_size; rot++) 
        {
            for (int32_t i = 0; i < text.size(); i++) 
            {
                text[i] = text_sav[(i + rot) % text.size()];
            }
            seal::Plaintext text_pln = bgv.encode(text);

            for (int32_t i = 0; i < 2; i++) 
            {
                auto p = rand.get_integer_vector<int64_t>(1, prime / 2, pattern_size);
                auto a = rand.get_integer<int64_t>(1, prime / 2) * rand.get_integer<int64_t>({ -1, 1 });
                auto r = rand.get_integer_vector<int64_t>(-prime / 2, prime / 2, text.size());

                for (int32_t j = 0; j < r.size(); j++) {
                    hash[rot][j] += sha256(std::to_string(r[j]));
                }

                result_e[rot][i] = bgv.sub(pattern_enc, text_pln);
                result_e[rot][i] = bgv.multiply(result_e[rot][i], bgv.encode(p));
                result_e[rot][i] = bgv.multiply(result_e[rot][i], bgv.encode(std::vector<int64_t>(1, a)));
                result_e[rot][i] = bgv.add(result_e[rot][i], bgv.encode(r));
            }
        }

        return std::make_pair(result_e, hash);
    };

    // create Alice function
    auto alice = [&]() {
        seal::Ciphertext pattern_enc;
        std::vector<int64_t> pattern_sav(pattern);
        int32_t pattern_size = pattern_sav.size();

        pattern.reserve(text.size());
        while (pattern.size() + pattern_sav.size() <= text.size()) {
            pattern.insert(pattern.end(), pattern_sav.begin(), pattern_sav.end());
        }

        pattern_enc = bgv.encrypt(bgv.encode(pattern));

        // send to bob
        auto [result_enc, hash] = bob(pattern_enc, pattern_size);

        // analyzing result
        matched.clear();

        for (int32_t rot = 0; rot < pattern_size; rot++) {
            std::vector<std::vector<int64_t>> result(2);

            for (int32_t i = 0; i < 2; i++) {
                result[i] = bgv.decode<int64_t>(bgv.decrypt(result_enc[rot][i]));
            }

            for (int32_t i = static_cast<int32_t>(pattern_size) - 1; i < static_cast<int32_t>(text.size()) - rot; i += pattern_size) {
                std::string hashing_result = "";

                for (int32_t j = 0; j < 2; j++) {
                    hashing_result += sha256(std::to_string(result[j][i]));
                }

                if (hashing_result == hash[rot][i]) {
                    matched.push_back(static_cast<int64_t>(i) - pattern_size + 1 + rot);
                }
            }
        }
    };

    alice();
}

void PatternMatch::integer_hash_primitive_root_in_bgv(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int64_t>& matched) {
    //text = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3 };
    //pattern = { 3, 0, 1 };

    // Random module
    RandomGenerator rand;


    // Create bgv
    she::SHE& bgv = she::SHEBuilder()
        .sec_level(she::sec_level_t::tc128)
        .mul_mode(she::mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(she::int_scheme_t::bgv, static_cast<size_t>(pow(2, 14)), 59, { 60, 60, 60, 60 ,60 });

    // Get plain modulus prime
    int64_t prime = bgv.plain_modulus_prime();


    // Set n(=the number of integers)
    int64_t n = std::max(
        *std::max_element(text.begin(), text.end()),
        *std::max_element(pattern.begin(), pattern.end())
    ) + 1;


    // Create n-th primitive root' powers
    double_t pi = 3.1415926535897932384626433832795028842;

    std::vector<std::complex<double_t>> powers(n);

    for (size_t k = 0; k < n; ++k)
    {
        double_t angle = 2.0 * pi * k / static_cast<double_t>(n);
        powers[k] = std::polar(1.0, angle);
    }

    powers.push_back(powers.front());


    // Calculate magnification
    int64_t p_half = prime / 2;
    double_t m_upper = std::sqrt(p_half / static_cast<int64_t>(pattern.size()));
    int64_t m = std::pow(10, std::floor(std::log10(m_upper)));
    std::cout << "magnification: " << m << " (prime: " << prime << ")\n";


    // Create Bob function
    auto bob = [&](std::vector<seal::Ciphertext>& pattern_e, std::vector<seal::Plaintext> &expected_sum_p)
    {
        // convert text
        std::vector<std::vector<int64_t>> text_o(2);

        text_o[0].reserve(text.size());
        text_o[1].reserve(text.size());

        for (auto& c : text)
        {
            text_o[0].push_back(static_cast<int64_t>(powers[c].real() * m));
            text_o[1].push_back(static_cast<int64_t>(powers[c].imag() * m));
        }

        std::reverse(text_o[0].begin(), text_o[0].end());
        std::reverse(text_o[1].begin(), text_o[1].end());

        // calculate: (t * p - es) * s + r
        std::vector<seal::Ciphertext> result_e(2);
        std::vector<std::string> hash(text.size(), "");

        for (size_t i = 0; i < 2; i++)
        {   
            auto s = std::vector<int64_t>(1, rand.get_integer<int64_t>(1, prime / 2) * rand.get_integer<int64_t>({ -1, 1 }));
            auto r = rand.get_integer_vector<int64_t>(1, prime / 2, text.size());

            for (size_t j = 0; j < r.size(); j++)
            {
                hash[j] += sha256(std::to_string(r[j]));
            }

            result_e[i] = bgv.multiply(pattern_e[i], bgv.encode(text_o[i]));
            result_e[i] = bgv.sub(result_e[i], expected_sum_p[i]);
            result_e[i] = bgv.multiply(result_e[i], bgv.encode(s));
            result_e[i] = bgv.add(result_e[i], bgv.encode(r));
        }

        return std::make_pair(result_e, hash);
    };


    // create Alice function
    auto alice = [&]() 
    {
        // convert text
        std::vector<std::vector<int64_t>> pattern_o(2);
        std::vector<std::vector<int64_t>> expected_sum_o(2);

        pattern_o[0].reserve(pattern.size());
        pattern_o[1].reserve(pattern.size());
        int64_t expected_sum0 = 0;
        int64_t expected_sum1 = 0;

        for (auto& c : pattern)
        {
            pattern_o[0].push_back(static_cast<int64_t>(powers[n - c].real() * m));
            pattern_o[1].push_back(static_cast<int64_t>(powers[n - c].imag() * m));
            expected_sum0 += static_cast<int64_t>(powers[n - c].real() * m) * static_cast<int64_t>(powers[c].real() * m);
            expected_sum1 += static_cast<int64_t>(powers[n - c].imag() * m) * static_cast<int64_t>(powers[c].imag() * m);
        }

        expected_sum_o[0].assign(bgv.slot_count(), expected_sum0);
        expected_sum_o[1].assign(bgv.slot_count(), expected_sum1);

        // send to bob
        std::vector<seal::Ciphertext> pattern_e(2);
        std::vector<seal::Plaintext> expected_sum_p(2);
        
        for (size_t i = 0; i < 2; i++)
        {
            pattern_e[i] = bgv.encrypt(bgv.encode(pattern_o[i]));
            expected_sum_p[i] = bgv.encode(expected_sum_o[i]);
        }  

        auto [result_e, hash] = bob(pattern_e, expected_sum_p);

        // analyzing result
        matched.clear();
        std::vector<std::vector<int64_t>> result(2);

        for (size_t i = 0; i < 2; i++) 
        {
            result[i] = bgv.decode<int64_t>(bgv.decrypt(result_e[i]));
        }

        for (size_t i = 0; i < text.size(); i++)
        {
            std::string hashing_result = "";

            for (size_t j = 0; j < 2; j++) 
            {
                hashing_result += sha256(std::to_string(result[j][i]));
            }

            if (hashing_result == hash[i]) 
            {
                matched.push_back(static_cast<int64_t>(text.size()) - static_cast<int64_t>(i) - static_cast<int64_t>(1));
            }
        }
    };

    alice();
}

void PatternMatch::integer_hash_primitive_root_in_ckks(std::vector<int64_t> text, std::vector<int64_t> pattern, std::vector<int64_t>& matched) {
    //text = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3 };
    //pattern = { 3, 0, 1 };
    //std::cout << std::fixed << std::setprecision(16);
    //const int width = 18;


    // Random module
    RandomGenerator rand;


    // Create ckks
    she::SHE& ckks = she::SHEBuilder()
        .sec_level(she::sec_level_t::tc128)
        .mul_mode(she::mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_real_complex_scheme(she::real_complex_scheme_t::ckks, static_cast<size_t>(pow(2, 14)), pow(2, 55), {60, 55, 55, 55, 55, 55 ,60});


    // Set n(=the number of integers)
    int64_t n = std::max(
        *std::max_element(text.begin(), text.end()),
        *std::max_element(pattern.begin(), pattern.end())
    ) + 1;


    // Create n-th primitive root' powers
    double_t pi = 3.1415926535897932384626433832795028842;

    std::vector<std::complex<double_t>> powers(n);

    for (size_t k = 0; k < n; ++k)
    {
        double_t angle = 2.0 * pi * k / static_cast<double_t>(n);
        powers[k] = std::polar(1.0, angle);
    }

    powers.push_back(powers.front());


    // Calculate precision
   /* int64_t decimal_place = static_cast<int64_t>(std::floor(std::log10(std::pow(2, 55)))) - 2;
    int64_t err_upper = (decimal_place * 2) - std::ceil(std::log10(std::pow(10, decimal_place) * pattern.size()));
    double_t p = std::pow(10, err_upper);
    std::cout << "precision: " << p << ' ' << decimal_place << ' ' << err_upper << '\n';*/
    double_t p = std::pow(10, static_cast<int64_t>(std::floor(std::log10(std::pow(2, 55)))) - 3);
    std::cout << "precision: " << p << '\n';

    // Create Bob function
    auto bob = [&](std::vector<seal::Ciphertext>& pattern_e, std::vector<seal::Plaintext>& expected_sum_p)
    {
        // convert text
        std::vector<std::vector<std::complex<double_t>>> text_o(2);

        if (text.size() <= ckks.slot_count())
        {
            text_o[0].reserve(text.size());
            text_o[1].reserve(text.size());

            for (size_t i = 0; i < text.size(); i++)
            {
                int64_t c = text[i];
                text_o[0].push_back(std::complex<double_t>(powers[c].real(), 0));
                text_o[1].push_back(std::complex<double_t>(powers[c].imag(), 0));
            }
        }
        else
        {
            text_o[0].reserve(ckks.slot_count());
            text_o[1].reserve(ckks.slot_count());

            for (size_t i = 0; i < ckks.slot_count(); i++)
            {
                if (i + ckks.slot_count() < text.size())
                {
                    int64_t c1 = text[i];
                    int64_t c2 = text[i + ckks.slot_count()];
                    text_o[0].push_back(std::complex<double_t>(powers[c1].imag(), powers[c2].imag()));
                    text_o[1].push_back(std::complex<double_t>(powers[c1].real(), powers[c2].real()));           
                }
                else
                {
                    int64_t c = text[i];
                    text_o[0].push_back(std::complex<double_t>(powers[c].real(), 0));
                    text_o[1].push_back(std::complex<double_t>(powers[c].imag(), 0));
                }
            }
        }

        std::reverse(text_o[0].begin(), text_o[0].end());
        std::reverse(text_o[1].begin(), text_o[1].end());

        // calculate: (t * p - es) * s + r
        std::vector<seal::Ciphertext> result_e(2);
        std::vector<std::string> hash(ckks.slot_count() * 2, "");

        for (size_t i = 0; i < 2; i++)
        {
            auto s_temp = static_cast<double_t>(rand.get_integer<int64_t>(1, static_cast<int64_t>(p) - 1)) / p;
            auto r_temp = rand.get_integer_vector<int64_t>(1, static_cast<int64_t>(p) - 1, ckks.slot_count() * 2);

            std::vector<std::complex<double_t>> s;
            std::vector<std::complex<double_t>> r;
           
            s.assign(1, std::complex<double_t>(s_temp, 0));
            r.reserve(ckks.slot_count());

            for (size_t j = 0; j < ckks.slot_count(); j++)
            {
                r.push_back(std::complex<double_t>(static_cast<double_t>(r_temp[j]) / p, static_cast<double_t>(r_temp[j + ckks.slot_count()]) / p));
                hash[j] += sha256(std::to_string(static_cast<int64_t>(std::floor(r_temp[j]))));
                hash[j + ckks.slot_count()] += sha256(std::to_string(static_cast<int64_t>(std::floor(r_temp[j]))));
                //std::cout << static_cast<int64_t>(std::floor(r[j])) << '\n';
            }
            //std::cout << '\n';

            result_e[i] = ckks.multiply(pattern_e[i], ckks.encode(text_o[i], pattern_e[i].parms_id(), pattern_e[i].scale()));
            result_e[i] = ckks.sub(result_e[i], expected_sum_p[i]);
            result_e[i] = ckks.multiply(result_e[i], ckks.encode(s, result_e[i].parms_id(), result_e[i].scale()));
            result_e[i] = ckks.add(result_e[i], ckks.encode(r, result_e[i].parms_id(), result_e[i].scale()));
        }

        return std::make_pair(result_e, hash);
    };


    // create Alice function
    auto alice = [&]()
    {
        // convert pattern
        std::vector<std::vector<std::complex<double_t>>> pattern_o(2);
        std::vector<std::vector<std::complex<double_t>>> expected_sum_o(2);

        double_t expected_sum0 = 0;
        double_t expected_sum1 = 0;

        if (pattern.size() <= ckks.slot_count())
        {
            pattern_o[0].reserve(pattern.size());
            pattern_o[1].reserve(pattern.size());

            for (size_t i = 0; i < pattern.size(); i++)
            {
                int64_t c = pattern[i];
                pattern_o[0].push_back(std::complex<double_t>(powers[n - c].real(), 0));
                pattern_o[1].push_back(std::complex<double_t>(powers[n - c].imag(), 0));
                expected_sum0 += powers[n - c].real() * powers[c].real();
                expected_sum1 += powers[n - c].imag() * powers[c].imag();
            }
        }
        else
        {
            pattern_o[0].reserve(ckks.slot_count());
            pattern_o[1].reserve(ckks.slot_count());

            for (size_t i = 0; i < ckks.slot_count(); i++)
            {
                if (i + ckks.slot_count() < pattern.size())
                {
                    int64_t c1 = pattern[i];
                    int64_t c2 = pattern[i + ckks.slot_count()];
                    pattern_o[0].push_back(std::complex<double_t>(powers[n - c1].real(), powers[n - c2].real()));
                    pattern_o[1].push_back(std::complex<double_t>(powers[n - c1].imag(), powers[n - c2].imag()));
                    expected_sum0 += powers[n - c1].real() * powers[c1].real();
                    expected_sum0 += powers[n - c2].real() * powers[c2].real();
                    expected_sum1 += powers[n - c1].imag() * powers[c1].imag();
                    expected_sum1 += powers[n - c2].imag() * powers[c2].imag();
                }
                else
                {
                    int64_t c = pattern[i];
                    pattern_o[0].push_back(std::complex<double_t>(powers[n - c].real(), 0));
                    pattern_o[1].push_back(std::complex<double_t>(powers[n - c].imag(), 0));
                    expected_sum0 += powers[n - c].real() * powers[c].real();
                    expected_sum1 += powers[n - c].imag() * powers[c].imag();
                }
            }
        }

        expected_sum_o[0].assign(ckks.slot_count(), std::complex<double_t>({ expected_sum0, expected_sum0 }));
        expected_sum_o[1].assign(ckks.slot_count(), std::complex<double_t>({ expected_sum1, expected_sum1 }));

        // send to bob
        std::vector<seal::Ciphertext> pattern_e(2);
        std::vector<seal::Plaintext> expected_sum_p(2);

        for (size_t i = 0; i < 2; i++)
        {
            pattern_e[i] = ckks.encrypt(ckks.encode(pattern_o[i]));
            expected_sum_p[i] = ckks.encode(expected_sum_o[i]);
        }

        auto [result_e, hash] = bob(pattern_e, expected_sum_p);

        // analyzing result
        matched.clear();
        std::vector<std::vector<std::complex<double_t>>> result(2);

        for (size_t i = 0; i < 2; i++) 
        {
            result[i] = ckks.decode<std::complex<double_t>>(ckks.decrypt(result_e[i]));
        }

        for (size_t i = 0; i < ckks.slot_count() * 2; i++)
        {
            for (auto& err : std::vector<std::vector<int64_t>>{ {-1, -1}, {-1, 0}, {-1, 1}, {0, -1}, {0, 0}, {0, 1}, {1, -1}, {1, 0}, {1, 1} })
            {
                std::string hashing_result = "";

                if (i < ckks.slot_count())
                {
                    for (size_t j = 0; j < 2; j++)
                    {
                        hashing_result += sha256(std::to_string(static_cast<int64_t>(std::floor(result[j][i].real() * p + err[j]))));
                        //std::cout << static_cast<int64_t>(std::floor(result[j][i] * p + err[j])) << '\n';
                    }
                    //std::cout << '\n';
                }
                else
                {
                    for (size_t j = 0; j < 2; j++)
                    {
                        hashing_result += sha256(std::to_string(static_cast<int64_t>(std::floor(result[j][i - ckks.slot_count()].imag() * p + err[j]))));
                        //std::cout << static_cast<int64_t>(std::floor(result[j][i] * p + err[j])) << '\n';
                    }
                    //std::cout << '\n';
                }

                if (hashing_result == hash[i])
                {
                    matched.push_back(static_cast<int64_t>(text.size()) - static_cast<int64_t>(i) - static_cast<int64_t>(1));
                    break;
                }
            }
        }
    };

    alice();
}