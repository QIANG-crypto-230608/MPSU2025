#ifndef THRESHOLD_ELGAMAL_ENCRYPTION_H
#define THRESHOLD_ELGAMAL_ENCRYPTION_H

#include <vector>
#include <string>
#include <memory>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include "cryptoTools/Common/Defines.h"

using namespace osuCrypto;

class ThresholdElGamalEncryption {
public:
    ThresholdElGamalEncryption(size_t numParties, size_t threshold);
    ThresholdElGamalEncryption(const BIGNUM* publicKey, const BIGNUM* p, const BIGNUM* g);
    ~ThresholdElGamalEncryption();

    void generateKeys();
    void encrypt(const std::vector<uint8_t>& plaintext, std::pair<BIGNUM*, BIGNUM*>& ciphertext) const;
    void partialDecrypt(size_t partyIndex, const std::pair<BIGNUM*, BIGNUM*>& ciphertext, BIGNUM*& partialDecryption) const;
    void partialDecryptWithSecretShare(const std::pair<BIGNUM*, BIGNUM*>& ciphertext, const BIGNUM* secretShare, BIGNUM*& partialDecryption) const;
    void combinePartialDecryptions(const std::pair<BIGNUM*, BIGNUM*>& ciphertext, const std::vector<BIGNUM*>& partialDecryptions, const std::vector<size_t>& indices, std::vector<uint8_t>& plaintext) const;

    void multiplyCiphertexts(const std::pair<BIGNUM*, BIGNUM*>& c1,
                             const std::pair<BIGNUM*, BIGNUM*>& c2,
                             std::pair<BIGNUM*, BIGNUM*>& result) const;

    BIGNUM* xorBIGNUMWithBlock(const BIGNUM* bn, const osuCrypto::block& blk);

    const BIGNUM* getPublicKey() const;
    const BIGNUM* getP() const;
    const BIGNUM* getG() const;
    BIGNUM* getSecretShare(size_t partyIndex);

    void shuffleCiphertext(std::vector<std::pair<BIGNUM*, BIGNUM*>>&  vec);


    void sequentialDecrypt(const std::pair<BIGNUM*, BIGNUM*>& ciphertext, std::vector<uint8_t>& plaintext, size_t plaintextSize) const;

//private:
    size_t numParties;
    size_t threshold;
    BIGNUM* publicKeyBN;
    BIGNUM* p;
    BIGNUM* g;
    BIGNUM* q; // q = (p - 1) / 2
    BIGNUM* x;
    std::vector<BIGNUM*> secretShares;

    bool encryptionOnlyMode;

    void generateGroupParams(BN_CTX* ctx);
    void shamirSecretSharing(BN_CTX* ctx);

    void additiveSecretSharing(BN_CTX* ctx);

    void bytesToBIGNUM(const std::vector<uint8_t>& input, BIGNUM* bn) const;
    void BIGNUMToBytes(const BIGNUM* bn, std::vector<uint8_t>& output, size_t expectedSize) const;
    void BIGNUMToBytes(const BIGNUM* bn, std::vector<uint8_t>& output) const;
    void computeLagrangeCoefficients(const std::vector<size_t>& indices, std::vector<BIGNUM*>& lambdas, BN_CTX* ctx) const;

    void freeBIGNUMVector(std::vector<BIGNUM*>& vec) const;
};

#endif
