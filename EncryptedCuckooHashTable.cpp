#include "EncryptedCuckooHashTable.h"
#include <iostream>
#include <cstring>
#include <libkern/OSByteOrder.h>

using namespace osuCrypto;

std::vector<uint8_t> concatenateHashAndElement(const uint64_t& element){
    unsigned char full_hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(&element), sizeof(uint64_t), full_hash);

    unsigned  char truncated_hash[16];
    memcpy(truncated_hash, full_hash, 16);

    uint64_t element_be = OSSwapHostToBigInt64(element);

    std::vector<uint8_t> concatenatedValue(16 + sizeof(uint64_t));
    std::copy(truncated_hash, truncated_hash + 16, concatenatedValue.begin());
    std::copy(reinterpret_cast<const uint8_t*>(&element_be),
              reinterpret_cast<const uint8_t*>(&element_be) + sizeof(uint64_t),
              concatenatedValue.begin() + 16);

    return concatenatedValue;
}

