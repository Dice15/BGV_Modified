#include "examples.h"
#include "modules/she/shebuilder.h"
#include "modules/she/she.h"
#include "modules/random/randomgenerator.h"
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
        .default_mul_mode(mul_mode_t::convolution)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(she::int_scheme_t::bgv, static_cast<size_t>(pow(2, 14)), 20, { 40, 40, 40, 40, 40 });

    vector<int64_t> v1 = { 1,2,3,4,5,6,7,8,9,10 };
    vector<int64_t> v2 = { 10 };

    auto v1_p = bgv.encode(v1);
    auto v2_p = bgv.encode(v2);

    auto v1_c = bgv.encrypt(v1_p);
    auto v2_c = bgv.encrypt(v2_p);

    Ciphertext temp_c = v1_c;

    for (int i = 0; i < 3; i++) {
        temp_c = bgv.multiply(temp_c, v2_c);
        auto res_p = bgv.decrypt(temp_c);
        auto res = bgv.decode(res_p);
        print_vector(res, 10);
    }

    temp_c = bgv.add(temp_c, v1_c);
    auto res_p = bgv.decrypt(temp_c);
    auto res = bgv.decode(res_p);
    print_vector(res, 10);
}

void bgv_test_2() {
    SHE& bgv = SHEBuilder()
        .sec_level(sec_level_t::tc128)
        .default_mul_mode(mul_mode_t::element_wise)
        .secret_key(true)
        .public_key(true)
        .relin_keys(true)
        .galois_keys(false)
        .build_integer_scheme(she::int_scheme_t::bgv, static_cast<size_t>(pow(2, 14)), 30);

    vector<int64_t> v1 = { 1,2,3,4,5,6,7,8,9,10 };
    vector<int64_t> v2 = { 10 };

    auto v1_p = bgv.encode(v1);
    auto v2_p = bgv.encode(v2);

    auto v1_c = bgv.encrypt(v1_p);
    auto v2_c = bgv.encrypt(v2_p);

    Ciphertext temp_c = v1_c;

    for (int i = 0; i < 5; i++) {
        temp_c = bgv.multiply(temp_c, v2_c);
        auto res_p = bgv.decrypt(temp_c);
        auto res = bgv.decode(res_p);
        print_vector(res, 10);
    }

    temp_c = bgv.add(temp_c, v1_c);
    auto res_p = bgv.decrypt(temp_c);
    auto res = bgv.decode(res_p);
    print_vector(res, 10);
}

void main()
{
    bgv_test_1();
    //bgv_test_2();
}