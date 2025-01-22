#ifndef PARTY_H
#define PARTY_H

#include <vector>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <openssl/bn.h>
#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "ThresholdElGamalEncryption.h"
#include "EncryptedCuckooHashTable.h"


using namespace osuCrypto;

class Party{
public:
    Party(size_t n, PRNG& prng, double epsilon, size_t t, size_t partyIndex) : n(n), t(t),
    epsilon(epsilon), partyIndex(partyIndex),
    cuckoo_table(static_cast<std::size_t>(epsilon * n)),
    simple_table(static_cast<std::size_t>(epsilon * n)),
    simple_table_v(static_cast<std::size_t>(epsilon * n)){
        for (size_t i = 0; i < n; ++i) {
            X.push_back(prng.get<std::uint64_t>());
        }
    };


    ~Party() {};



    void displayElements() const;
    const std::vector<std::uint64_t>& getSetX() const;


    std::vector<std::uint64_t> X;
    size_t n;
    size_t t;
    BIGNUM* publicKey;
    BIGNUM* secretShare;
    BIGNUM* p;
    BIGNUM* g;
    size_t partyIndex;
    double epsilon;
    std::vector<uint64_t> cuckoo_table_v;
    std::vector<std::vector<uint64_t>> simple_table_v;
    std::vector<std::pair<BIGNUM*, BIGNUM*>> encrypted_cuckoo_table_v;
    std::vector<std::pair<BIGNUM*, BIGNUM*>> encrypted_zero_table_v;
    ENCRYPTO::CuckooTable cuckoo_table;
    ENCRYPTO::SimpleTable simple_table;
    std::vector<std::vector<block>> w;
    std::vector<std::vector<block>> r;
    std::vector<std::vector<block>> s_1; //Pi
    std::vector<std::vector<block>> s_2; //Pi+1
    std::vector<block> com_s_2;
    std::vector<block> a;
    std::vector<block> b;
    std::vector<std::pair<BIGNUM*, BIGNUM*>> A;
    std::vector<std::vector<block>> sw;
    std::vector<std::vector<block>> com_sw;
    std::vector<std::pair<BIGNUM*, BIGNUM*>> part_ciphertext;
    std::vector<std::uint64_t> union_result;

};

#endif // PARTY_H



