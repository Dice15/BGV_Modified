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

void main()
{
    // create bgv
    SEALHelper& bgv = SEALBuilder(seal::scheme_type::bgv, seal::sec_level_type::tc128, 8192, { 40, 40, 40, 40, 40 }, 20, false)
        .create_secret_key()
        .create_public_key()
        .create_relin_keys()
        .build();

    vector<int64_t> v1 = { 1,2,3,4,5,6,7,8,9,10 };
    vector<int64_t> v2 = { 10 };

    auto v1_p = bgv.encode(v1);
    auto v2_p = bgv.encode(v2);

    auto v1_c = bgv.encrypt(v1_p);
    auto v2_c = bgv.encrypt(v2_p);

    Ciphertext temp_c = v1_c;

    for (int i = 0; i < 10; i++) {
        temp_c = bgv.multiply(temp_c, v2_p);
        auto res_p = bgv.decrypt(temp_c);
        auto res = bgv.decode(res_p);
        print_vector(res, 10);
    }

    temp_c = bgv.add(temp_c, v1_p);
    auto res_p = bgv.decrypt(temp_c);
    auto res = bgv.decode(res_p);
    print_vector(res, 10);
}