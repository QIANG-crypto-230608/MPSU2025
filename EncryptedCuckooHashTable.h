#ifndef ENCRYPTED_CUCKOO_HASH_TABLE_H
#define ENCRYPTED_CUCKOO_HASH_TABLE_H

#include "ThresholdElGamalEncryption.h"
#include <vector>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include "cryptoTools/Common/Defines.h"

using namespace osuCrypto;



std::vector<uint8_t> concatenateHashAndElement(const uint64_t & element);

#endif
