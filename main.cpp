#include "examples.h"
#include "modules/she/shebuilder.h"
#include "modules/she/she.h"
#include "modules/random/randomgenerator.h"
#include "modules/simulator/patternmatch.h"
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
#include <type_traits>

using namespace std;
using namespace seal;
using namespace she;

void bgv_test_1() {
    SHE& bgv = SHEBuilder()
        .sec_level(sec_level_t::tc128)
        .mul_mode(mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(she::int_scheme_t::bgv, static_cast<size_t>(pow(2, 14)), 20);

    cout << bgv.plain_modulus_prime() / 2 << '\n';

    vector<int64_t> v1 = { 1,2,3,4,5,6,7,8,9,10 };
    vector<int64_t> v2 = { 2 };

    auto v1_p = bgv.encode(v1);
    auto v2_p = bgv.encode(v2);

    auto v1_c = bgv.encrypt(v1_p);
    auto v2_c = bgv.encrypt(v2_p);

    Ciphertext temp_c = v1_c;

    for (int i = 0; i < 8; i++) {
        temp_c = bgv.multiply(temp_c, v2_c);
        auto res_p = bgv.decrypt(temp_c);
        auto res = bgv.decode<int64_t>(res_p);
        print_vector(res, 10);
    }

    temp_c = bgv.add(temp_c, v1_p);
    auto res_p = bgv.decrypt(temp_c);
    auto res = bgv.decode<int64_t>(res_p);
    print_vector(res, 10);
}

void bgv_test_2() {
    SHE& bgv = SHEBuilder()
        .sec_level(sec_level_t::tc128)
        .mul_mode(mul_mode_t::element_wise)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(she::int_scheme_t::bgv, static_cast<size_t>(pow(2, 14)), 30);

    cout << bgv.plain_modulus_prime() / 2 << '\n';

    vector<int64_t> v1 = { 1,2,3,4,5,6,7,8,9,10 };
    vector<int64_t> v2 = { 2 };

    auto v1_p = bgv.encode(v1);
    auto v2_p = bgv.encode(v2);

    auto v1_c = bgv.encrypt(v1_p);
    auto v2_c = bgv.encrypt(v2_p);

    Ciphertext temp_c = v1_c;

    for (int i = 0; i < 4; i++) {
        temp_c = bgv.multiply(temp_c, v2_p);
        auto res_p = bgv.decrypt(temp_c);
        auto res = bgv.decode<int64_t>(res_p);
        print_vector(res, 10);
    }

    temp_c = bgv.add(temp_c, v1_p);
    auto res_p = bgv.decrypt(temp_c);
    auto res = bgv.decode<int64_t>(res_p);
    print_vector(res, 10);
}

void bgv_test_3() {
    SHE& bgv = SHEBuilder()
        .sec_level(sec_level_t::tc128)
        .mul_mode(mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_real_complex_scheme(she::real_complex_scheme_t::ckks, static_cast<size_t>(pow(2, 14)), pow(2, 40));

    vector<complex<double_t>> v1 = { {1,1},{2,2},{3,3},{4,4},{5,5},{6,6},{7,7},{8,8},{9,9},{10,10} };
    vector<complex<double_t>> v2 = { {2,0} };

    auto v1_p = bgv.encode(v1);
    auto v2_p = bgv.encode(v2);

    auto v1_c = bgv.encrypt(v1_p);
    auto v2_c = bgv.encrypt(v2_p);

    Ciphertext temp_c = v1_c;

    for (int i = 0; i < 7; i++) {
        temp_c = bgv.multiply(temp_c, v2_c);
        auto res_p = bgv.decrypt(temp_c);
        auto res = bgv.decode<complex<double_t>>(res_p);
        print_vector(res, 10, 3);
    }

    temp_c = bgv.add(temp_c, v1_p);
    auto res_p = bgv.decrypt(temp_c);
    auto res = bgv.decode<complex<double_t>>(res_p);
    print_vector(res, 10, 3);
}

void bgv_test_4() {
    SHE& bgv = SHEBuilder()
        .sec_level(sec_level_t::tc128)
        .mul_mode(mul_mode_t::element_wise)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_real_complex_scheme(she::real_complex_scheme_t::ckks, static_cast<size_t>(pow(2, 14)), pow(2, 30));

    vector<int64_t> v1 = { 1,2,3,4,5,6,7,8,9,10 };

    vector<int64_t> v2 = { 2 };

    auto v1_p = bgv.encode(v1);
    auto v2_p = bgv.encode(v2);

    auto v1_c = bgv.encrypt(v1_p);
    auto v2_c = bgv.encrypt(v2_p);

    Ciphertext temp_c = v1_c;

    for (int i = 0; i < 10; i++) {
        temp_c = bgv.multiply(temp_c, v2_p);
        auto res_p = bgv.decrypt(temp_c);
        auto res = bgv.decode<double_t>(res_p);
        print_vector(res, 10, 3);
    }

    temp_c = bgv.add(temp_c, v1_p);
    auto res_p = bgv.decrypt(temp_c);
    auto res = bgv.decode<double_t>(res_p);
    print_vector(res, 10, 3);
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
    PatternMatch simulator;

    /* {
        cout << "- hash + rotation in bgv" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_rotation_in_bgv);
        if (matched.empty()) {
            cout << endl << "    [ empty ]" << endl << endl;
        }
        else {
            sort(matched.begin(), matched.end());
            print_vector(matched, matched.size());
        }
        cout << "    Execution time: " << time << "ms" << endl << endl;
    }*/

    {
        cout << "- hash + primitive root in bgv" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_primitive_root_in_bgv);
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
        cout << "- hash + primitive root in ckks" << endl;
        auto [time, matched] = simulator.integer_matching(text, pattern, integer_matching_type::hash_primitive_root_in_ckks);
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


void main()
{
    int text_len = 1 << 13;
    int int_set = 26;
    vector<tuple<int32_t, int32_t, int32_t>> test_set;

    for (int i = 1000; i <= 10000; i *= 10) {
        test_set.push_back({ text_len , i, int_set });
    }

    for (auto& [text_size, pattern_size, unique_int_cnt] : test_set)
    {
        integer_matching(text_size, pattern_size, unique_int_cnt);
    }


    /*bgv_test_1();
    bgv_test_3();
    bgv_test_2();
    bgv_test_4();

    return;

   // return;
    RandomGenerator rand;

    size_t poly_modulus_degree = 1 << 14;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 55, 55, 60 }));
    double scale = 36028797017456641;// pow(2.0, 55);  // 10^16.5 < 2^55 = 36,028,797,018,963,968 < 10^16.6 (0.00000000000001미만의 오차 발생 -> 14자리 까지 정확히 예측 가능)

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
    CKKSEncoder encoder(context);
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
        //text[0].push_back(i + 1);
        //text[1].push_back(i + 1);
    }

   // text[0].assign((1 << 14) - 3, 2);
    //text[1].assign((1 << 14) - 3, 3);

    pattern[0].reserve(pattern_size);   // real(w^4 ~ w^6)
    pattern[1].reserve(pattern_size);   // imag(w^4 ~ w^6)
    double expected_m1 = 0.0;
    double expected_m2 = 0.0;
    for (int i = 0, j = 4; i < pattern_size; i++, j++) {
        pattern[0].push_back(powers[j].real());
        pattern[1].push_back(powers[j].imag());
        //pattern[0].push_back(1);
        //pattern[1].push_back(10);
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
        const double rn0 = static_cast<double>(rand.get_integer<int64_t>(1, pow(2, 46) - 1)) / 100000000000000.0;
        const double rn1 = static_cast<double>(rand.get_integer<int64_t>(1, pow(2, 46) - 1)) / 100000000000000.0;
        rn[0].push_back(rn0);
        rn[1].push_back(rn1);
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
        encoder.encode(pattern[i], scale, pattern_plain[i], seal::mul_mode_type::convolution);
        encryptor.encrypt(pattern_plain[i], pattern_cipher[i]);

        cout << pattern_cipher[i].scale() << ' ' << scale << '\n';
    }


    // calc
    Plaintext text_plain;
    Plaintext m_plain;
    Plaintext s_plain;
    Plaintext rn_plain;
    Ciphertext res_cipher[2];

    for (int i = 0; i < 2; i++) {
        //res_cipher[i] = pattern_cipher[i];
        cout << res_cipher[i].scale() * res_cipher[i].scale() << '\n';
        encoder.encode(text[i], pattern_cipher[i].scale(), text_plain, seal::mul_mode_type::convolution);
        evaluator.multiply_plain(pattern_cipher[i], text_plain, res_cipher[i]);
        evaluator.relinearize_inplace(res_cipher[i], relin_keys);

        auto ptr = context.get_context_data(res_cipher[i].parms_id());
        auto prime = ptr->parms().coeff_modulus().back().value();
        cout << res_cipher[i].scale() << ' ' << prime << ' ' << res_cipher[i].scale() / static_cast<double>(prime) << '\n';
        evaluator.rescale_to_next_inplace(res_cipher[i]);
        cout << res_cipher[i].scale() << '\n';

        for (auto& e : res_cipher[i].parms_id()) {
        
        }
        encoder.encode(m[i], scale, m_plain, seal::mul_mode_type::convolution);
        evaluator.mod_switch_to_inplace(m_plain, res_cipher[i].parms_id());
        evaluator.sub_plain(res_cipher[i], m_plain, res_cipher[i]);

        cout << res_cipher[i].scale() * res_cipher[i].scale() << '\n';
        encoder.encode(s[i], res_cipher[i].parms_id(), res_cipher[i].scale(), s_plain, seal::mul_mode_type::convolution);
        //evaluator.mod_switch_to_inplace(s_plain, res_cipher[i].parms_id());
        evaluator.multiply_plain(res_cipher[i], s_plain, res_cipher[i]);
        evaluator.relinearize_inplace(res_cipher[i], relin_keys);

        ptr = context.get_context_data(res_cipher[i].parms_id());
        ptr = context.get_context_data(res_cipher[i].parms_id());
        prime = ptr->parms().coeff_modulus().back().value();
        cout << res_cipher[i].scale() << ' ' << prime << ' ' << res_cipher[i].scale() / static_cast<double>(prime) << '\n';
        evaluator.rescale_to_next_inplace(res_cipher[i]);
        cout << res_cipher[i].scale() << '\n';

        encoder.encode(rn[i], res_cipher[i].scale(), rn_plain, seal::mul_mode_type::convolution);
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
        encoder.decode(res_plain[i], res[i], seal::mul_mode_type::convolution);
        cout << res[i].size() << '\n';
        cout << (i == 0 ? "Real part matching" : "Imag part matching") << '\n';
        for (int j = 0; j < text_size; j++) {
            double diff = abs(res[i][j] - rn[i][j]);

            cout << "(" << right << setw(width) << res[i][j]
                << ") - (" << right << setw(width) << rn[i][j]
                << ") = (" << right << setw(width) << diff
                << ") : " << right << (static_cast<int64_t>(floor(diff * pow(10, 14))) == 0LL ? "matched" : "not-matched")
                << '\n';
        }
    }*/
}

/*
  0.000000000000001
(-0.000000000000000333066907387547) - ( 0.392039265987880025665646144262) = ( 0.392039265987880358732553531809) : not-matched
( 0.000000000000000000000000000000) - ( 0.098983078919070002776869898753) = ( 0.098983078919070002776869898753) : not-matched
( 0.000000000000001582067810090848) - ( 0.576286163411659946298470913462) = ( 0.576286163411658391986236438242) : not-matched
(-0.000000000000000194289029309402) - ( 0.365065413854549991601317060486) = ( 0.365065413854550158134770754259) : not-matched
(-0.000000000000000444089209850063) - ( 0.348778728365999990401746799762) = ( 0.348778728366000434490956649825) : not-matched
(-0.000000000000000693889390390723) - ( 0.282889047227669998552102015310) = ( 0.282889047227670720197068021662) : not-matched
( 0.000000000000000860422844084496) - ( 0.271880677591749997379366732275) = ( 0.271880677591749164712098263408) : not-matched
(-0.000000000000001193489751472043) - ( 0.261304956675459998383104220920) = ( 0.261304956675461164117280077335) : not-matched
(-0.000000000000000249800180540660) - ( 0.305657005762040023810754973965) = ( 0.305657005762040245855359898997) : not-matched
( 0.000000000000001165734175856414) - ( 0.286395482459219974380459916574) = ( 0.286395482459218808646284060160) : not-matched
( 0.000000000000000777156117237610) - ( 0.580143616193390054824874368933) = ( 0.580143616193389277668757131323) : not-matched
(-0.000000000000000693889390390723) - ( 0.221438967214739990119198864704) = ( 0.221438967214740684008589255427) : not-matched
(-0.000000000000000832667268468867) - ( 0.157744242554869990025068204886) = ( 0.157744242554870822692336673754) : not-matched
( 0.000000000000000555111512312578) - ( 0.456065337008390025985704596678) = ( 0.456065337008389470874192284100) : not-matched
(-0.000000000000152107026239772480) - ( 0.624047940478759999294311455742) = ( 0.624047940478912099848685102188) : not-matched
(-0.000000000000011944162085743459) - ( 0.293947074719849987811670644078) = ( 0.293947074719861922709185364511) : not-matched
( 0.000000000000043301543665506381) - ( 0.375067674966430009142470680672) = ( 0.375067674966386710444510299567) : not-matched
(-0.000000000000015627020179563541) - ( 0.636303127538569990306882573350) = ( 0.636303127538585644451529788057) : not-matched
( 0.000000000000088090682289271908) - ( 0.357027476776110019862642275257) = ( 0.357027476776021923665638269085) : not-matched
(-0.000000000000022593134966749026) - ( 0.207319106275610010037269148597) = ( 0.207319106275632603075820270533) : not-matched
( 0.000000000000014982327471858602) - ( 0.415277236032540020271852654332) = ( 0.415277236032525032261020214719) : not-matched
(-0.000000000000014458053321346307) - ( 0.147069936427830005865047269253) = ( 0.147069936427844466519943011917) : not-matched
(-0.000000000000014359085377637966) - ( 0.618116006449820010182349960814) = ( 0.618116006449834332059367625334) : not-matched
( 0.000000000000097868477644680817) - ( 0.446126787796999990654001067014) = ( 0.446126787796902124494380359465) : not-matched
( 0.000000000000238709051253777361) - ( 0.334361010435950012364969552436) = ( 0.334361010435711314414675143780) : not-matched
(-0.000000000000069034108325422165) - ( 0.014858121498330000703758102532) = ( 0.014858121498399034024484599570) : not-matched
(-0.000000000000011056946884610381) - ( 0.293097808413090021861791001356) = ( 0.293097808413101068580886021664) : not-matched
( 0.000000000000099527193501637811) - ( 0.648303659349260041899754014594) = ( 0.648303659349160565916747600568) : not-matched
( 0.000000000000078007045267725061) : not-matched
( 0.000000000000165534252971610840) : not-matched
( 0.000000000000000888178419700125) : matched
( 0.000000000000001998401444325282) : matched
( 0.000000000000001776356839400250) : matched
( 0.000000000000000083266726846887) : matched
( 0.000000000000003441691376337985) : matched
*/