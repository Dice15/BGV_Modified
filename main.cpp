#include "examples.h"
#include "modules/bgv/BGVBuilder.h"
#include "modules/bgv/BGVSeal.h"
#include "modules/random/RandomGenerator.h"
#include "modules/algorithm/Huffman.h"
#include "modules/algorithm/FFT.h"
#include "modules/simulator/MatchingSimulator.h"
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <chrono>
#include <thread>
#include <set>
#include <limits>

#include <fstream>
#include <sstream>
#include <iomanip> 
#include <future>
#include <thread>

using namespace std;
using namespace seal;

void binary_matching(const int32_t text_size = 2048, const int32_t pattern_size = 10) {
    cout << endl << "------------------ <Testing integer matching: text size(" << text_size << "), pattern size(" << pattern_size << ")> ------------------" << endl << endl;


    // Generate random data
    RandomGenerator rand;

    vector<int16_t> text = rand.get_integer_vector<int16_t>({ 0, 1 }, text_size);
    vector<int16_t> pattern = rand.get_integer_vector<int16_t>({ 0, 1 }, pattern_size);

    for (auto& i : rand.get_integer_vector<int32_t>(0, text.size() - pattern.size(), rand.get_integer(3, 100))) {
        for (int64_t j = 0; j < pattern.size(); j++) {
            if (i + j < text.size()) {
                text[i + j] = pattern[j];
            }
        }
    }

    cout << "Text:";
    print_vector(text, std::min(10, static_cast<int32_t>(text.size())));
    cout << "Pattern:";
    print_vector(pattern, std::min(10, static_cast<int32_t>(pattern.size())));


    //Testing
    MatchingSimulator simulator;

    {
        cout << "- hash" << endl;
        auto [time, matched] = simulator.binary_matching(text, pattern, binary_matching_type::hash);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }

    {
        cout << "- hash + rotation" << endl;
        auto [time, matched] = simulator.binary_matching(text, pattern, binary_matching_type::hash_rotation);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }
}

void integer_matching(const int32_t text_size = 2048, const int32_t pattern_size = 10, const int32_t unique_int_cnt = 4) {
    cout << endl << "------------------ <Testing integer matching: text size(" << text_size << "), pattern size(" << pattern_size << ")> ------------------" << endl << endl;


    // Generate random data
    RandomGenerator rand;

    set<int16_t> int_set = rand.get_integer_set<int16_t>(
        std::numeric_limits<int16_t>::min(),
        std::numeric_limits<int16_t>::max(),
        unique_int_cnt);

    vector<int16_t> text = rand.get_integer_vector<int16_t>(vector<int16_t>(int_set.begin(), int_set.end()), text_size);
    vector<int16_t> pattern = rand.get_integer_vector<int16_t>(vector<int16_t>(int_set.begin(), int_set.end()), pattern_size);

    for (auto& i : rand.get_integer_vector<int32_t>(0, text.size() - pattern.size(), rand.get_integer(3, 100))) {
        for (int64_t j = 0; j < pattern.size(); j++) {
            if (i + j < text.size()) {
                text[i + j] = pattern[j];
            }
        }
    }

    cout << "Text:";
    print_vector(text, std::min(10, static_cast<int32_t>(text.size())));
    cout << "Pattern:";
    print_vector(pattern, std::min(10, static_cast<int32_t>(pattern.size())));


    //Testing
    MatchingSimulator simulator;

    {
        cout << "- hash + primitive root" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_primitive_root);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }

    {
        cout << "- hash + rotation" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_rotation);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }

    {
        cout << "- hash + power" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_power);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }
}


std::vector<uint64_t> calculate_mod_frequencies_from_balanced_sets(int sub_set_size, int full_set_size) {
    std::random_device rd;
    std::mt19937 gen(rd());

    std::vector<int> full_set(full_set_size);
    std::iota(full_set.begin(), full_set.end(), 0);

    std::vector<int> set1(sub_set_size);
    std::sample(full_set.begin(), full_set.end(), set1.begin(), sub_set_size, gen);

    std::vector<int> set2(sub_set_size);
    for (int i = 0; i < sub_set_size; ++i) {
        set2[i] = (full_set_size - set1[i]) % full_set_size;
    }

    std::vector<uint64_t> mod_results(full_set_size, 0);

    for (int a : set1) {
        for (int b : set2) {
            int result = (a + b) % full_set_size;
            mod_results[result]++;
        }
    }

    return mod_results;
}

std::vector<uint64_t> calculate_mod_frequencies_from_unbalanced_sets(int sub_set_size, int full_set_size, int start_index) {
    /*std::vector<int> set1(sub_set_size);
    for (int i = 0; i < sub_set_size; ++i) {
        set1[i] = (start_index + i) % full_set_size;
    }

    std::vector<int> set2(sub_set_size);
    for (int i = 0; i < sub_set_size; ++i) {
        set2[i] = (full_set_size - set1[i]) % full_set_size;
    }

    std::vector<uint64_t> mod_results(full_set_size, 0);

    for (int a : set1) {
        for (int b : set2) {
            int result = (a + b) % full_set_size;
            mod_results[result]++;
        }
    }

    return mod_results;*/

    RandomGenerator rand;
    auto temp = rand.get_integer_vector<int64_t>(0, full_set_size - 1, full_set_size, rand.get_random_weights(full_set_size));
    std::vector<uint64_t> mod_results(full_set_size, 0);
    for (int i = 0; i < full_set_size; i++) {
        mod_results[i] = temp[i];
        //cout << temp[i] << ' ';
    }
    //cout << '\n';
    return mod_results;
}

std::unordered_map<uint64_t, double_t> count_ordered_permutations_mod_prob(
    const std::vector<uint64_t>& powers,
    const std::vector<uint64_t>& frequencies,
    const uint64_t min_m,
    const uint64_t max_m,
    const uint64_t p,
    const std::unordered_map<uint64_t, uint64_t>& target_mods)
{
    uint64_t total_freq = 0;
    for (const uint64_t& freq : frequencies) {
        total_freq += freq;
    }

    std::vector<std::vector<double_t>> dp(2, std::vector<double_t>(p, 0.0));
    dp[0][0] = 1.0;

    std::unordered_map<uint64_t, double_t> counts;

    for (uint64_t m = 1; m <= max_m; ++m) {
        std::cout << "  Processing m = " << m << '\n';

        auto& dp_prev = dp[(m + 1) % 2];
        auto& dp_curr = dp[m % 2];

        std::fill(dp_curr.begin(), dp_curr.end(), 0.0);

        for (uint64_t current_sum = 0; current_sum < p; ++current_sum) {
            double_t current_prob = dp_prev[current_sum];
            if (current_prob == 0.0) continue;

            for (uint64_t i = 0; i < powers.size(); ++i) {
                uint64_t power = powers[i];
                uint64_t freq = frequencies[i];
                uint64_t new_sum = (current_sum + power) % p;
                dp_curr[new_sum] += current_prob * (static_cast<double_t>(freq) / static_cast<double_t>(total_freq));
            }
        }

        if (target_mods.find(m) != target_mods.end()) {
            uint64_t target_mod = target_mods.at(m);
            double_t desired_prob = dp_curr[target_mod];

            desired_prob -= std::pow(static_cast<double>(frequencies[0]) / static_cast<double>(total_freq), m);
            counts[m] = desired_prob;
        }
    }

    return counts;
}

double_t compute_mixing_time(const vector<uint64_t>& powers, const vector<uint64_t>& frequencies, uint64_t p, double_t epsilon = 0.01) {
    uint64_t total = 0;
    for (const auto& freq : frequencies) {
        total += freq;
    }

    // 빈도수를 확률로 정규화
    vector<double_t> mu(p, 0.0);
    for (size_t i = 0; i < powers.size(); ++i) {
        mu[powers[i]] += static_cast<double_t>(frequencies[i]) / static_cast<double_t>(total);
    }

    // FFT 객체 생성 및 FFT 수행
    FFT fft;
    vector<complex<double_t>> eigenvalues = fft.compute_fft(mu);

    // 고유값의 절댓값 계산
    vector<double_t> abs_eigenvalues;
    abs_eigenvalues.reserve(p);

    for (int i = 0; i < p; ++i) {
        double_t magnitude = abs(eigenvalues[i]);
        abs_eigenvalues.push_back(magnitude);
    }

    // 두 번째로 큰 고유값 찾기 (k >=1)
    double_t second_largest_eigenvalue = 0.0;
    if (p > 1) {
        second_largest_eigenvalue = *max_element(abs_eigenvalues.begin() + 1, abs_eigenvalues.end());
    }

    // 스펙트럼 갭 계산
    double_t spectral_gap = 1.0 - second_largest_eigenvalue;

    if (spectral_gap <= 0.0) {
        throw runtime_error("스펙트럼 갭이 0 이하입니다. 랜덤 워크가 혼합되지 않습니다.");
    }

    // 혼합 시간 계산
    double_t mixing_time = log(1.0 / epsilon) / spectral_gap;

    return mixing_time;
}

void probabiity_of_root_of_unity(uint64_t unique_int_cnt, uint64_t factor, uint64_t prime_bit_size, bool calc_wrong_prob) {
    // print CPU cores
    unsigned int num_cores = std::thread::hardware_concurrency();
    std::cout << "Number of CPU cores: " << num_cores << '\n';


    // calculate n
    uint64_t n = static_cast<uint64_t>(1) << static_cast<uint64_t>(ceil(log2(unique_int_cnt)));
    cout << "    Unique int cnt = " << unique_int_cnt << ", n = " << n << '\n';


    // random module
    RandomGenerator rand;


    // create plain modulus
    seal::Modulus plain_modulus = seal::PlainModulus::Batching(factor, prime_bit_size);


    // get plain modulus prime
    uint64_t prime = plain_modulus.value();
    cout << "      Prime = " << prime << '\n';


    // create nth-primitive roots using plain modulus prime
    std::vector<uint64_t> roots;
    seal::util::try_primitive_roots(n, plain_modulus, 1, roots);
    uint64_t root = roots[0];
    cout << "      Primitive Root = " << root << '\n';


    // calculate powers
    std::vector<uint64_t> powers;
    uint64_t power = 1;

    powers.reserve(n);
    while (powers.size() < n) {
        powers.push_back(power);
        power = (power * root) % prime;
    }


    // create subset
    std::vector<uint64_t> original_set_frequencies(n, 1);
    std::vector<uint64_t> unbalanced_sub_set_frequencies(n, 0);

    unbalanced_sub_set_frequencies[0] = 75;
    unbalanced_sub_set_frequencies[1] = 15;
    unbalanced_sub_set_frequencies[2] = 5;
    unbalanced_sub_set_frequencies[3] = 5;


    // calculate mixing time
    double_t original_set_mixing_time = 0.0;
    double_t unbalanced_subset_mixing_time = 0.0;

    auto future_original_set_mixing_time = std::async(std::launch::async, compute_mixing_time, powers, original_set_frequencies, prime, 0.01);
    auto future_unbalanced_subset_mixing_time = std::async(std::launch::async, compute_mixing_time, powers, unbalanced_sub_set_frequencies, prime, 0.01);

    original_set_mixing_time = future_original_set_mixing_time.get();
    unbalanced_subset_mixing_time = future_unbalanced_subset_mixing_time.get();


    uint64_t max_mixing_time = min(static_cast<uint64_t>(150), static_cast<uint64_t>(ceil(max(original_set_mixing_time, unbalanced_subset_mixing_time))));

    cout << std::fixed << std::setprecision(std::numeric_limits<double_t>::max_digits10);
    cout << "\n    For unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
    cout << "      Original Set Mixing Time      = " << original_set_mixing_time << '\n';
    cout << "      Unbalanced Subset Mixing Time = " << unbalanced_subset_mixing_time << '\n';


    // calculate prob
    std::unordered_map<uint64_t, double_t> original_set_wrong_prob;
    std::unordered_map<uint64_t, double_t> unbalanced_subset_wrong_prob;

    if (calc_wrong_prob) {
        std::unordered_map<uint64_t, uint64_t> target_mods;

        for (uint64_t m = 1; m <= max_mixing_time; m++) {
            target_mods.insert({ m, m % prime });
        }

        cout << "\n    For m = " << max_mixing_time << ", unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';

        auto future_original_set = std::async(std::launch::async, count_ordered_permutations_mod_prob, powers, original_set_frequencies, 1, max_mixing_time, prime, target_mods);
        auto future_unbalanced_subset = std::async(std::launch::async, count_ordered_permutations_mod_prob, powers, unbalanced_sub_set_frequencies, 1, max_mixing_time, prime, target_mods);

        original_set_wrong_prob = future_original_set.get();
        unbalanced_subset_wrong_prob = future_unbalanced_subset.get();
    }


    // create text file
    std::ostringstream filename;
    filename << "unique_cnt=" << unique_int_cnt << "_n=" << n << "_p=" << prime << ".txt";
    std::ofstream out(filename.str());


    // write result
    out << "    For unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
    out << "      Primitive Root = " << root << '\n';
    out << "      Powers         = [";
    for (auto& e : powers) out << e << ", "; out << "]\n";

    out << "    For unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
    out << "      Original Set Frequencies      = [";
    for (auto& e : original_set_frequencies) out << e << ", "; out << "]\n";

    out << "      Unbalanced Subset Frequencies = [";
    for (auto& e : unbalanced_sub_set_frequencies) out << e << ", "; out << "]\n";


    out << std::fixed << std::setprecision(std::numeric_limits<double_t>::max_digits10);
    out << "    For unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
    out << "      Original Set Mixing Time      = " << original_set_mixing_time << '\n';
    out << "      Unbalanced Subset Mixing Time = " << unbalanced_subset_mixing_time << '\n';

    if (calc_wrong_prob) {
        for (uint64_t m = 1; m <= max_mixing_time; m++) {
            auto prob_original_set = original_set_wrong_prob[m] * 100.0;
            auto prob_unbalanced_subset = unbalanced_subset_wrong_prob[m] * 100.0;

            auto both_prob_original_set = prob_original_set * prob_original_set / 100.0;
            auto both_prob_unbalanced_subset = prob_unbalanced_subset * prob_unbalanced_subset / 100.0;

            auto prob_theoretical_single_set = static_cast<double_t>(1) / (static_cast<double_t>(prime) / 100.0);
            auto prob_theoretical_both_set = pow(prob_theoretical_single_set, 2) / 100.0;

            out << "    For m = " << m << ", unique_int_cnt = " << unique_int_cnt << ", n = " << n << ", p = " << prime << ": " << '\n';
            out << "      Convergence Single Probability     = " << prob_theoretical_single_set << '\n';
            out << "      Original Set Probability           = " << prob_original_set << '\n';
            out << "      Unbalanced Subset Probability      = " << prob_unbalanced_subset << '\n';

            out << "      Convergence Both Probability       = " << prob_theoretical_both_set << '\n';
            out << "      Both Original Set Probability      = " << both_prob_original_set << '\n';
            out << "      Both Unbalanced Subset Probability = " << both_prob_unbalanced_subset << '\n';
        }
    }
}

vector<complex<double>> calculate_powers_of_root(size_t n) {
    const double PI = 3.1415926535897932384626433832795028842;
    if (n == 0) {
        throw invalid_argument("n must be greater than 0");
    }

    vector<complex<double>> powers(n + 1);

    for (size_t k = 0; k <= n; ++k) {
        double angle = 2.0 * PI * k / static_cast<double>(n);
        powers[k] = polar(1.0, angle);
    }

    return powers;
}


void main()
{
    RandomGenerator rand;

    size_t poly_modulus_degree = 1 << 15;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 55, 55, 55, 60 }));
    double scale = pow(2.0, 55);  // 10^16.5 < 2^55 = 36,028,797,018,963,968 < 10^16.6 (0.00000000000001미만의 오차 발생 -> 14자리 까지 정확히 예측 가능)

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context, false);
    size_t slot_count = encoder.slot_count();
    size_t logn = util::get_power_of_two(parms.poly_modulus_degree());

    cout << "Number of slots: " << slot_count << endl;
    cout << "Modulus Bit: " << logn << endl;
    print_parameters(context);
    cout << endl;

    cout << fixed << setprecision(30);
    const int width = 33;

    vector<double> text[2];
    vector<double> pattern[2];
    vector<double> m[2];
    vector<double> s[2];
    vector<double> rn[2];


    // init example data
    int unique_char_num = 8;
    int text_size = 16;
    int pattern_size = 3;
    auto powers = calculate_powers_of_root(unique_char_num);

    text[0].reserve(text_size);   // real(w^0 ~ w^7)
    text[1].reserve(text_size);   // imag(w^0 ~ w^7)
    for (int i = 0; i < text_size; i++) {
        text[0].push_back(powers[i % unique_char_num].real());
        text[1].push_back(powers[i % unique_char_num].imag());
        //text[0].push_back(1);
        //text[1].push_back(1);
    }

    pattern[0].reserve(pattern_size);   // real(w^4 ~ w^6)
    pattern[1].reserve(pattern_size);   // imag(w^4 ~ w^6)
    double expected_m1 = 0.0;
    double expected_m2 = 0.0;
    for (int i = 0, j = 4; i < pattern_size; i++, j++) {
        pattern[0].push_back(powers[j].real());
        pattern[1].push_back(powers[j].imag());
        //pattern[0].push_back(1);
        //pattern[1].push_back(1);
        expected_m1 += powers[j].real() * powers[unique_char_num - j].real();
        expected_m2 += powers[j].imag() * powers[unique_char_num - j].imag();
    }



    m[0].assign(text_size, expected_m1);   // real(w^4 ~ w^6)
    m[1].assign(text_size, expected_m2);   // imag(w^4 ~ w^6)

    for (int i = 0; i < 2; i++) {
        // 소수점 14자리까지만 유효하므로, 46비트 사용. 1미만인 값으로 만들어야 소수점 14자리까지 값을 오차 없이 지킬 수 있음.
        s[i].assign(1, static_cast<double>(rand.get_integer<int64_t>(1, pow(2, 46) - 1)) / 100000000000000.0);
    }

    rn[0].reserve(text_size);
    rn[1].reserve(text_size);
    while (rn[0].size() < text_size) {
        rn[0].push_back(static_cast<double>(rand.get_integer<int64_t>(1, pow(2, 46) - 1)) / 100000000000000.0);
        rn[1].push_back(static_cast<double>(rand.get_integer<int64_t>(1, pow(2, 46) - 1)) / 100000000000000.0);
    }

    print_vector(text[0], 8);
    print_vector(text[1], 8);
    print_vector(pattern[0], 8);
    print_vector(pattern[1], 8);
    cout << expected_m1 << '\n';
    cout << expected_m2 << '\n';
    print_vector(s[0], 8);
    print_vector(s[1], 8);
    print_vector(rn[0], 8);
    print_vector(rn[1], 8);


    // pattern encrypt
    Plaintext pattern_plain[2];
    Ciphertext pattern_cipher[2];

    for (int i = 0; i < 2; i++) {
        encoder.encode(pattern[i], scale, pattern_plain[i]);
        encryptor.encrypt(pattern_plain[i], pattern_cipher[i]);
    }


    // calc
    Plaintext text_plain;
    Plaintext m_plain;
    Plaintext s_plain;
    Plaintext rn_plain;
    Ciphertext res_cipher[2];

    for (int i = 0; i < 2; i++) {
        encoder.encode(text[i], pattern_cipher[i].scale(), text_plain);
        evaluator.multiply_plain(pattern_cipher[i], text_plain, res_cipher[i]);
        evaluator.relinearize_inplace(res_cipher[i], relin_keys);
        evaluator.rescale_to_next_inplace(res_cipher[i]);

        encoder.encode(m[i], res_cipher[i].scale(), m_plain);
        evaluator.mod_switch_to_inplace(m_plain, res_cipher[i].parms_id());
        evaluator.sub_plain(res_cipher[i], m_plain, res_cipher[i]);

        encoder.encode(s[i], res_cipher[i].scale(), s_plain);
        evaluator.mod_switch_to_inplace(s_plain, res_cipher[i].parms_id());
        evaluator.multiply_plain(res_cipher[i], s_plain, res_cipher[i]);
        evaluator.relinearize_inplace(res_cipher[i], relin_keys);
        evaluator.rescale_to_next_inplace(res_cipher[i]);

        encoder.encode(rn[i], res_cipher[i].scale(), rn_plain);
        evaluator.mod_switch_to_inplace(rn_plain, res_cipher[i].parms_id());
        evaluator.add_plain(res_cipher[i], rn_plain, res_cipher[i]);
    }


    // decrypt
    Plaintext res_plain[2];
    for (int i = 0; i < 2; i++) {
        decryptor.decrypt(res_cipher[i], res_plain[i]);
    }


    // decode
    vector<double> res[2];
    for (int i = 0; i < 2; i++) {
        encoder.decode(res_plain[i], res[i]);

        cout << (i == 0 ? "Real part matching" : "Imag part matching") << '\n';
        for (int j = 0; j < text_size; j++) {
            double diff = abs(res[i][j] - rn[i][j]);

            cout << "(" << right << setw(width) << res[i][j]
                << ") - (" << right << setw(width) << rn[i][j]
                << ") = (" << right << setw(width) << diff
                << ") : " << right << (static_cast<int64_t>(floor(diff * pow(10, 14))) == 0LL ? "matched" : "not-matched")
                << '\n';
        }
    }
}


/*
    0.000000000000001 << 15자리 부터 오차 존재.
    0.000000000000000666133814775094
    0.000000000000001776356839400250
    0.000000000000005329070518200751
    0.000000000000000333066907387547
    0.000000000000001998401444325282
    0.000000000000000444089209850063
    0.000000000000000444089209850063
    0.000000000000000888178419700125
    0.000000000000000971445146547012
    0.000000000000001332267629550188
    0.000000000000000444089209850063
    0.000000000000002664535259100376
    0.000000000000002803313137178520
    0.000000000000002664535259100376
    0.000000000000000333066907387547

CKKSEncoder::CKKSEncoder -  57
Number of slots: 16384
Modulus Bit: 15

| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 32768
|   coeff_modulus size: 285 (60 + 55 + 55 + 55 + 60) bits

Real part matching
(-1.010732579096475403090948930185) - ( 0.518943653269799964888875365432) = ( 1.529676232366275367979824295617) : not-matched
(-1.580261070633564912668589386158) - ( 0.202860218327069991017808092693) = ( 1.783121288960634931441973094479) : not-matched
(-0.917756923777534816544232398883) - ( 0.305984062115490007549567508249) = ( 1.223740985893024824093799907132) : not-matched
(-0.307078809685701448195516150008) - ( 0.178069154963629988630557932083) = ( 0.485147964649331409070498466463) : not-matched
( 0.248002843372918169162488766233) - ( 0.248002843372920001030479397741) = ( 0.000000000000001831867990631508) : matched
( 0.230853239860283998563517116054) - ( 0.283343429739179974991003518880) = ( 0.052490189878895976427486402827) : not-matched
(-0.292125822700155080013928454719) - ( 0.319744670246350004561008972814) = ( 0.611870492946505084574937427533) : not-matched
(-1.033295560652304212467811339593) - ( 0.317167953537890012771782721757) = ( 1.350463514190194169728442830092) : not-matched
(-1.787178076919191171967327136372) - ( 0.048433401920339999580100709409) = ( 1.835611478839531240936366884853) : not-matched
(-1.284331506034902092849847576872) - ( 0.498789782925730007523412723458) = ( 1.783121288960632044862109069072) : not-matched
(-0.956059334654741022063717537094) - ( 0.267681651238280027271798644506) = ( 1.223740985893021049335516181600) : not-matched
(-0.066728024447734499147166786770) - ( 0.418419940201600004670012822316) = ( 0.485147964649334517694967416901) : not-matched
( 0.155228538543252803094674163731) - ( 0.155228538543249999781536985211) = ( 0.000000000000002803313137178520) : matched
( 0.348978125881034328958918422359) - ( 0.401468315759929972319497437638) = ( 0.052490189878895643360579015280) : not-matched
( 0.075593227687373296119766052925) - ( 0.687463720633879948884725763492) = ( 0.611870492946506638887171902752) : not-matched
(-1.205021662428036544056908496714) - ( 0.145441851762160012651037277465) = ( 1.350463514190196612219097005436) : not-matched

Imag part matching
( 0.699213740669131111893364050047) - ( 0.585340965968879967107341144583) = ( 0.113872774700251144786022905464) : not-matched
( 0.239330229797072274733338304031) - ( 0.125457455096819991968715157782) = ( 0.113872774700252282764623146250) : not-matched
( 0.454060291828649265077899599419) - ( 0.378145108695150000688300906404) = ( 0.075915183133499264389598693015) : not-matched
( 0.068767062801826525642034937391) - ( 0.062254569679009996718832553597) = ( 0.006512493122816528923202383794) : not-matched
( 0.475539898693177309763058246972) - ( 0.475539898693179974298317347348) = ( 0.000000000000002664535259100376) : matched
( 0.656807387593679514736777491635) - ( 0.596614753682150000813066981209) = ( 0.060192633911529513923710510426) : not-matched
( 0.560569548664498706891379242734) - ( 0.408739182397500011578728162931) = ( 0.151830366266998695312651079803) : not-matched
( 0.922730034700965262572935898788) - ( 0.701496978423279959891090129531) = ( 0.221233056277685302681845769257) : not-matched
( 0.869920245149257143069121411827) - ( 0.642174695748759960522988876619) = ( 0.227745549400497182546132535208) : not-matched
( 0.763115819698722996911044447188) - ( 0.595562904209759991225325848063) = ( 0.167552915488963005685718599125) : not-matched
( 0.238942696884599459217213279771) - ( 0.163027513751100000538585277354) = ( 0.075915183133499458678628002417) : not-matched
( 0.211805688651547890932747009174) - ( 0.205293195528729988108551651749) = ( 0.006512493122817902824195357425) : not-matched
( 0.565251080825450280542554537533) - ( 0.565251080825449947475647149986) = ( 0.000000000000000333066907387547) : matched
( 0.641889417713795151776423608680) - ( 0.581696783802259975715287509956) = ( 0.060192633911535176061136098724) : not-matched
( 0.383441279398457901539387648882) - ( 0.231610913131460011138429422317) = ( 0.151830366266997890400958226564) : not-matched
( 0.225764980337783194297429645303) - ( 0.004531924060100000171968925855) = ( 0.221233056277683193258098981460) : not-matched
*/