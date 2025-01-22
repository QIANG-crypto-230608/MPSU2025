cmake_minimum_required(VERSION 3.29)
project(MPSU LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)


find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(cryptoTools REQUIRED)
find_package(libOTe REQUIRED)
find_package(ENCRYPTO_utils REQUIRED)
find_package(RELIC REQUIRED)
find_package(ABY REQUIRED)
find_package(OpenMP REQUIRED)
find_package(fmt REQUIRED)
find_package(NTL REQUIRED)
find_package(GMP REQUIRED)


#####################################################################################
include_directories("/usr/local/include")
link_directories("/usr/local/lib")

set(MIRACL_INCLUDE_DIR "/usr/local/include")
set(MIRACL_LIBRARY "/usr/local/lib/libmiracl.a")
include_directories(${MIRACL_INCLUDE_DIR})
#####################################################################################

add_executable(MPSU main.cpp
        Party.h
        Party.cpp
        ThresholdElGamalEncryption.h
        ThresholdElGamalEncryption.cpp
        EncryptedCuckooHashTable.h
        EncryptedCuckooHashTable.cpp
        Eval.h
        polynomials/Poly.h
        polynomials/Poly.cpp
        polynomials/Mersenne.h
        polynomials/Mersenne.cpp
        ots/ots.h
        ots/ots.cpp
        common/constants.h
        common/helpers.h
        common/helpers.cpp
        common/psi_analytics_context.h
        common/psi_analytics.h
        common/psi_analytics.cpp
        HashingTables/common/hash_table_entry.h
        HashingTables/common/hash_table_entry.cpp
        HashingTables/common/hashing.h
        HashingTables/common/hashing.cpp
        HashingTables/common/util.h
        HashingTables/cuckoo_hashing/cuckoo_hashing.h
        HashingTables/cuckoo_hashing/cuckoo_hashing.cpp
        HashingTables/simple_hashing/simple_hashing.h
        HashingTables/simple_hashing/simple_hashing.cpp
        OSN/benes.h
        OSN/benes.cpp
        OSN/OSN.cpp
        OSN/OSN.h
        BETORG/BEtORG.h
        BETORG/BEtORG.cpp
        BIGNUM_Trans_operation.h
        BIGNUM_Trans_operation.cpp
        BETORG/batch_equality.h
)

target_link_libraries(MPSU PUBLIC ntl gmp OpenSSL::SSL OpenSSL::Crypto ${Boost_LIBRARIES} ${RELIC_LIB} libcryptoTools.a OpenMP::OpenMP_CXX ${FMT_LIBRARY} ${MIRACL_LIBRARY} pthread oc::libOTe librelic_s.a  libencrypto_utils.a libaby.a)
target_include_directories(MPSU PUBLIC ${CMAKE_SOURCE_DIR}/EZPC/SCI/src)
