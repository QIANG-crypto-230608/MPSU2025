// Party.cpp
#include "Party.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <iostream>

using namespace osuCrypto;

//Party::Party(size_t n, PRNG& prng){
//    for (size_t i = 0; i < n; ++i) {
//        X.push_back(prng.get<std::uint64_t>());
//    }
//}


void Party::displayElements() const {
    std::cout << "Elements in X:" << std::endl;
    for (const auto& element : X) {
        std::cout << element << std::endl;
    }
}

const std::vector<std::uint64_t>& Party::getSetX() const {
    return X;
}


