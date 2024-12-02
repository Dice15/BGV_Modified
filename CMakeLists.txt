cmake_minimum_required(VERSION 3.8)

project("bgv_modified")

# 라이브러리 경로 설정
set(SEAL_DIR "C:/Users/user/Desktop/mpc/SEAL/build")
set(FFTW3_DIR "C:/Users/user/Desktop/mpc/vcpkg-master/packages/fftw3_x64-windows-static/share/fftw3")
set(OPENSSL_ROOT_DIR "C:/Users/user/Desktop/mpc/vcpkg-master/installed/x64-windows")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libcrypto.lib")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libssl.lib")

# 실행 파일 정의
add_executable(bgv_modified
    "bgv_modified.h"
    "main.cpp"
    "examples.h"

    # SHE Modules
    "modules/she/shebuilder.h"
    "modules/she/shebuilder.cpp"
    "modules/she/she.h"
    "modules/she/she.cpp"
    "modules/she/common.h"

    # Random Generator Modules
    "modules/random/randomgenerator.h"
    "modules/random/randomgenerator.cpp"
 "modules/simulator/patternmatch.h" "modules/simulator/patternmatch.cpp")

# MS SEAL
find_package(SEAL REQUIRED PATHS ${SEAL_DIR})
target_link_libraries(bgv_modified PRIVATE SEAL::seal)

# OpenSSL
find_package(OpenSSL REQUIRED)
target_include_directories(bgv_modified PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(bgv_modified PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})

# FFTW3
find_package(FFTW3 CONFIG REQUIRED)
target_link_libraries(bgv_modified PRIVATE FFTW3::fftw3)

# Standard C++
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET bgv_modified PROPERTY CXX_STANDARD 20)
endif()
