#include "ThresholdElGamalEncryption.h"
#include <iostream>
#include <random>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

using namespace osuCrypto;

ThresholdElGamalEncryption::ThresholdElGamalEncryption(size_t numParties, size_t threshold)
        : numParties(numParties), threshold(threshold), encryptionOnlyMode(false),
          publicKeyBN(NULL), p(NULL), g(NULL), q(NULL), x(NULL) {
    secretShares.resize(numParties, nullptr);
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }
    generateGroupParams(ctx);
    BN_CTX_free(ctx);
}

ThresholdElGamalEncryption::ThresholdElGamalEncryption(const BIGNUM* publicKey, const BIGNUM* p, const BIGNUM* g)
        : encryptionOnlyMode(true), publicKeyBN(NULL), p(NULL), g(NULL), q(NULL), x(NULL) {
    if (!publicKey || !p || !g) {
        throw std::runtime_error("Public parameters are not properly initialized");
    }
    publicKeyBN = BN_dup(publicKey);
    this->p = BN_dup(p);
    this->g = BN_dup(g);

    //q = (p - 1) / 2
    BN_CTX* ctx = BN_CTX_new();
    q = BN_new();
    BN_sub(q, this->p, BN_value_one()); // q = p - 1
    BN_div_word(q, 2); // q = (p - 1) / 2
    BN_CTX_free(ctx);
}


ThresholdElGamalEncryption::~ThresholdElGamalEncryption() {
    if (publicKeyBN) {
        BN_free(publicKeyBN);
        publicKeyBN = NULL;
    }
    if (p) {
        BN_free(p);
        p = NULL;
    }
    if (g) {
        BN_free(g);
        g = NULL;
    }
    if (q) {
        BN_free(q);
        q = NULL;
    }
    if (!encryptionOnlyMode) {
        if (x) {
            BN_free(x);
            x = NULL;
        }
        for (auto& share : secretShares) {
            if (share) {
                BN_free(share);
                share = NULL;
            }
        }
        secretShares.clear();
    }
}



//


void ThresholdElGamalEncryption::generateKeys() {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    // private key x ∈ [1, q-1]， x is even
    x = BN_new();
    if (!x) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for x");
    }

    while (true) {
        if (BN_rand_range(x, q) != 1) {
            BN_free(x);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to generate random x");
        }

        if (BN_is_bit_set(x, 0) == 0 && BN_cmp(x, BN_value_one()) > 0) {
            break;
        }
    }

    //h = g^x mod p
    publicKeyBN = BN_new();
    if (!publicKeyBN) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for publicKeyBN");
    }
    if (BN_mod_exp(publicKeyBN, g, x, p, ctx) != 1) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute h = g^x mod p");
    }

    BIGNUM* sum = BN_new();
    if (!sum) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for sum");
    }
    BN_zero(sum);

    for (size_t i = 0; i < numParties - 1; ++i) {
        secretShares[i] = BN_new();
        if (!secretShares[i]) {
            BN_free(sum);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to allocate BIGNUM for secret share");
        }
        if (BN_rand_range(secretShares[i], q) != 1) {
            BN_free(sum);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to generate random secret share");
        }
        if (BN_mod_add(sum, sum, secretShares[i], q, ctx) != 1) {
            BN_free(sum);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to compute sum of shares");
        }
    }

    // x - sum mod q
    secretShares[numParties - 1] = BN_new();
    if (!secretShares[numParties - 1]) {
        BN_free(sum);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for final secret share");
    }
    if (BN_mod_sub(secretShares[numParties - 1], x, sum, q, ctx) != 1) {
        BN_free(sum);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute final secret share");
    }

    BIGNUM* verify = BN_new();
    if (!verify) {
        BN_free(sum);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for verification");
    }
    BN_zero(verify);
    for (size_t i = 0; i < numParties; ++i) {
        if (BN_mod_add(verify, verify, secretShares[i], q, ctx) != 1) {
            BN_free(verify);
            BN_free(sum);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to compute sum for verification");
        }
    }

    if (BN_cmp(verify, x) != 0) {
        BN_free(verify);
        BN_free(sum);
        BN_CTX_free(ctx);
        throw std::runtime_error("Secret shares do not sum up to the original secret x");
    }

    BN_free(verify);
    BN_free(sum);
    BN_CTX_free(ctx);
}

void ThresholdElGamalEncryption::encrypt(const std::vector<uint8_t>& plaintext, std::pair<BIGNUM*, BIGNUM*>& ciphertext) const {
    if (!publicKeyBN || !p || !g) {
        throw std::runtime_error("Public parameters are not initialized");
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BIGNUM* k = BN_new();
    if (!k) {
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for k");
    }

    while (true) {
        if (BN_rand_range(k, q) != 1) {
            BN_free(k);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to generate random k");
        }

        if (BN_is_bit_set(k, 0) == 0 && BN_cmp(k, BN_value_one()) > 0) {
            break;
        }
    }

    BIGNUM* c1 = BN_new();
    if (!c1) {
        BN_free(k);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for c1");
    }
    if (BN_mod_exp(c1, g, k, p, ctx) != 1) {
        BN_free(k);
        BN_free(c1);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute c1 = g^k mod p");
    }

    BIGNUM* h_k = BN_new();
    if (!h_k) {
        BN_free(k);
        BN_free(c1);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for h_k");
    }
    if (BN_mod_exp(h_k, publicKeyBN, k, p, ctx) != 1) {
        BN_free(k);
        BN_free(c1);
        BN_free(h_k);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute h^k mod p");
    }


    BIGNUM* plaintextBN = BN_new();
    if (!plaintextBN) {
        BN_free(k);
        BN_free(c1);
        BN_free(h_k);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for plaintext");
    }
    if (BN_bin2bn(plaintext.data(), plaintext.size(), plaintextBN) == NULL) {
        BN_free(k);
        BN_free(c1);
        BN_free(h_k);
        BN_free(plaintextBN);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to convert plaintext to BIGNUM");
    }

    if (BN_cmp(plaintextBN, p) >= 0) {
        BN_free(k);
        BN_free(c1);
        BN_free(h_k);
        BN_free(plaintextBN);
        BN_CTX_free(ctx);
        throw std::runtime_error("Plaintext is too large");
    }

    BIGNUM* c2 = BN_new();
    if (!c2) {
        BN_free(k);
        BN_free(c1);
        BN_free(h_k);
        BN_free(plaintextBN);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to allocate BIGNUM for c2");
    }
    if (BN_mod_mul(c2, plaintextBN, h_k, p, ctx) != 1) {
        BN_free(k);
        BN_free(c1);
        BN_free(h_k);
        BN_free(plaintextBN);
        BN_free(c2);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute c2 = m * h^k mod p");
    }

    ciphertext.first = c1;
    ciphertext.second = c2;

    BN_free(k);
    BN_free(h_k);
    BN_free(plaintextBN);
    BN_CTX_free(ctx);
}


BIGNUM* ThresholdElGamalEncryption::getSecretShare(size_t partyIndex){
    if (partyIndex >= numParties) {
        throw std::runtime_error("Invalid party index");
    }
    return secretShares[partyIndex];
}


void ThresholdElGamalEncryption::partialDecryptWithSecretShare(const std::pair<BIGNUM*, BIGNUM*>& ciphertext, const BIGNUM* secretShare, BIGNUM*& partialDecryption) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    // c_i = c1^{s_i} mod p
    partialDecryption = BN_new();
    BN_mod_exp(partialDecryption, ciphertext.first, secretShare, p, ctx);

    BN_CTX_free(ctx);
}


void ThresholdElGamalEncryption::combinePartialDecryptions(const std::pair<BIGNUM*, BIGNUM*>& ciphertext, const std::vector<BIGNUM*>& partialDecryptions, const std::vector<size_t>& indices, std::vector<uint8_t>& plaintext) const {
    if (partialDecryptions.size() < threshold || indices.size() < threshold) {
        throw std::runtime_error("Not enough partial decryptions to meet the threshold");
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    std::vector<BIGNUM*> lambdas;
    computeLagrangeCoefficients(indices, lambdas, ctx);

    BIGNUM* numerator = BN_new();
    BN_one(numerator);

    for (size_t i = 0; i < threshold; ++i) {
        BIGNUM* temp = BN_new();
        BN_mod_exp(temp, partialDecryptions[i], lambdas[i], p, ctx);
        BN_mod_mul(numerator, numerator, temp, p, ctx);
        BN_free(temp);
    }


    BIGNUM* denominator = BN_mod_inverse(NULL, numerator, p, ctx);
    if (!denominator) {
        BN_free(numerator);
        BN_CTX_free(ctx);
        throw std::runtime_error("Failed to compute inverse in decryption");
    }


    BIGNUM* plaintextBN = BN_new();
    BN_mod_mul(plaintextBN, ciphertext.second, denominator, p, ctx);


    BIGNUMToBytes(plaintextBN, plaintext);

    BN_free(numerator);
    BN_free(denominator);
    BN_free(plaintextBN);
    freeBIGNUMVector(lambdas);
    BN_CTX_free(ctx);
}

const BIGNUM* ThresholdElGamalEncryption::getPublicKey() const {
    return publicKeyBN;
}

const BIGNUM* ThresholdElGamalEncryption::getP() const {
    return p;
}

const BIGNUM* ThresholdElGamalEncryption::getG() const {
    return g;
}





void ThresholdElGamalEncryption::generateGroupParams(BN_CTX* ctx) {

    q = BN_new();
    if (!q) {
        throw std::runtime_error("Failed to allocate BIGNUM for q");
    }

    p = BN_new();
    if (!p) {
        BN_free(q);
        throw std::runtime_error("Failed to allocate BIGNUM for p");
    }

    g = BN_new();
    if (!g) {
        BN_free(q);
        BN_free(p);
        throw std::runtime_error("Failed to allocate BIGNUM for g");
    }

    BIGNUM* h = BN_new();
    if (!h) {
        BN_free(q);
        BN_free(p);
        BN_free(g);
        throw std::runtime_error("Failed to allocate BIGNUM for h");
    }

    bool p_is_prime = false;
    int attempt = 0;
    const int max_attempts = 10000;

    while (!p_is_prime && attempt < max_attempts) {
        attempt++;

        //q = 1024/2048
        if (BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL) != 1) {
            throw std::runtime_error("Failed to generate prime q");
        }

        // p = 2q + 1
        if (!BN_lshift1(p, q)) { // temp = q << 1
            throw std::runtime_error("Failed to compute p = 2q");
        }
        if (!BN_add(p, p, BN_value_one())) { // p = temp + 1
            throw std::runtime_error("Failed to compute p = 2q + 1");
        }

        if (BN_check_prime(p, ctx, NULL) == 1) {
            p_is_prime = true;
        } else {
        }
    }

    if (!p_is_prime) {
        BN_free(q);
        BN_free(p);
        BN_free(g);
        BN_free(h);
        throw std::runtime_error("Failed to generate a prime p after maximum attempts");
    }

    bool g_found = false;
    for (int i = 2; i < 100 && !g_found; ++i) {
        if (BN_set_word(g, i) != 1) {
            throw std::runtime_error("Failed to set g word");
        }

        if (BN_mod_exp(h, g, q, p, ctx) != 1) {
            throw std::runtime_error("Failed to compute h = g^q mod p");
        }

        if (BN_cmp(h, BN_value_one()) != 0) {
            g_found = true;
        }
    }

    BN_free(h);

    if (!g_found) {
        BN_free(q);
        BN_free(p);
        BN_free(g);
        throw std::runtime_error("Failed to find a valid generator g");
    }
}



void ThresholdElGamalEncryption::shamirSecretSharing(BN_CTX* ctx) {
    std::vector<BIGNUM*> coeffs(threshold);
    coeffs[0] = BN_dup(x);

    for (size_t i = 1; i < threshold; ++i) {
        coeffs[i] = BN_new();
        BN_rand_range(coeffs[i], q);
    }

    for (size_t i = 1; i <= numParties; ++i) {
        BIGNUM* x_i = BN_new();
        BN_set_word(x_i, i);

        BIGNUM* y_i = BN_new();
        BN_zero(y_i);

        for (size_t j = 0; j < threshold; ++j) {
            BIGNUM* term = BN_new();
            BN_one(term);

            // term = coeffs[j] * x_i^j mod q
            for (size_t k = 0; k < j; ++k) {
                BN_mod_mul(term, term, x_i, q, ctx);
            }
            BN_mod_mul(term, term, coeffs[j], q, ctx);
            BN_mod_add(y_i, y_i, term, q, ctx);
            BN_free(term);
        }

        secretShares[i - 1] = y_i;

        BN_free(x_i);
    }

    freeBIGNUMVector(coeffs);
}




void ThresholdElGamalEncryption::bytesToBIGNUM(const std::vector<uint8_t>& input, BIGNUM* bn) const {
    BN_bin2bn(input.data(), input.size(), bn);
}

void ThresholdElGamalEncryption::BIGNUMToBytes(const BIGNUM* bn, std::vector<uint8_t>& output) const {
    int numBytes = BN_num_bytes(bn);
    output.resize(numBytes);
    BN_bn2bin(bn, output.data());
}

void ThresholdElGamalEncryption::computeLagrangeCoefficients(const std::vector<size_t>& indices, std::vector<BIGNUM*>& lambdas, BN_CTX* ctx) const {
    size_t t = indices.size();
    lambdas.resize(t);

    for (size_t i = 0; i < t; ++i) {
        BIGNUM* num = BN_new();
        BN_one(num);
        BIGNUM* den = BN_new();
        BN_one(den);

        for (size_t j = 0; j < t; ++j) {
            if (i != j) {
                BIGNUM* xi = BN_new();
                BIGNUM* xj = BN_new();
                BN_set_word(xi, indices[i] + 1); // xi = indices[i] + 1
                BN_set_word(xj, indices[j] + 1); // xj = indices[j] + 1

                BIGNUM* diff = BN_new();
                BN_sub(diff, xj, xi); // diff = xj - xi

                if (BN_is_negative(diff)) {
                    BN_add(diff, diff, q); // diff = diff + q
                }

                BN_mod_mul(num, num, xj, q, ctx);
                BN_mod_mul(den, den, diff, q, ctx);

                BN_free(xi);
                BN_free(xj);
                BN_free(diff);
            }
        }

        BIGNUM* den_inv = BN_mod_inverse(NULL, den, q, ctx);
        if (!den_inv) {
            BN_free(num);
            BN_free(den);
            throw std::runtime_error("Failed to compute inverse in Lagrange coefficients");
        }

        lambdas[i] = BN_new();
        BN_mod_mul(lambdas[i], num, den_inv, q, ctx);

        BN_free(num);
        BN_free(den);
        BN_free(den_inv);
    }
}


void ThresholdElGamalEncryption::freeBIGNUMVector(std::vector<BIGNUM*>& vec) const {
    for (auto& bn : vec) {
        BN_free(bn);
    }
    vec.clear();
}

void ThresholdElGamalEncryption::multiplyCiphertexts(const std::pair<BIGNUM*, BIGNUM*>& c1,
                                                     const std::pair<BIGNUM*, BIGNUM*>& c2,
                                                     std::pair<BIGNUM*, BIGNUM*>& result) const {
    if (!p) {
        throw std::runtime_error("Public parameters are not initialized");
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    BIGNUM* r_a = BN_new();
    BIGNUM* r_b = BN_new();

    //  r_a = c1_a * c2_a mod p
    BN_mod_mul(r_a, c1.first, c2.first, p, ctx);
    //  r_b = c1_b * c2_b mod p
    BN_mod_mul(r_b, c1.second, c2.second, p, ctx);

    result.first = r_a;
    result.second = r_b;

    BN_CTX_free(ctx);
}

BIGNUM* ThresholdElGamalEncryption::xorBIGNUMWithBlock(const BIGNUM* bn, const osuCrypto::block& blk) {
    if (!bn) return nullptr;

    constexpr size_t block_size = sizeof(osuCrypto::block);
    uint8_t blk_bytes[block_size];
    memcpy(blk_bytes, &blk, block_size);

    int bn_size = BN_num_bytes(bn);
    std::vector<uint8_t> bn_bytes(bn_size, 0);
    BN_bn2bin(bn, bn_bytes.data());

    size_t max_size = std::max(static_cast<size_t>(bn_size), block_size);
    std::vector<uint8_t> aligned_bn(max_size, 0);
    std::vector<uint8_t> aligned_blk(max_size, 0);

    std::copy(bn_bytes.begin(), bn_bytes.end(), aligned_bn.begin() + (max_size - bn_size));

    std::reverse_copy(blk_bytes, blk_bytes + block_size, aligned_blk.begin() + (max_size - block_size));

    std::vector<uint8_t> result_bytes(max_size, 0);
    for (size_t i = 0; i < max_size; ++i) {
        result_bytes[i] = aligned_bn[i] ^ aligned_blk[i];
    }

    BIGNUM* result = BN_bin2bn(result_bytes.data(), max_size, nullptr);

    return result;
}


//random_shuffle
void ThresholdElGamalEncryption::shuffleCiphertext(std::vector<std::pair<BIGNUM*, BIGNUM*>>&  vec)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(vec.begin(), vec.end(), gen);
}



void ThresholdElGamalEncryption::additiveSecretSharing(BN_CTX* ctx) {
    freeBIGNUMVector(secretShares);

    std::vector<BIGNUM*> shares(numParties, nullptr);
    BIGNUM* sum = BN_new();
    BN_zero(sum);

    for (size_t i = 0; i < numParties - 1; ++i) {
        shares[i] = BN_new();
        if (!shares[i]) {
            freeBIGNUMVector(shares);
            BN_free(sum);
            throw std::runtime_error("Failed to allocate BIGNUM for secret share");
        }
        if (BN_rand_range(shares[i], q) != 1) {
            freeBIGNUMVector(shares);
            BN_free(sum);
            throw std::runtime_error("Failed to generate random secret share");
        }
        BN_mod_add(sum, sum, shares[i], q, ctx);
    }

    shares[numParties - 1] = BN_new();
    if (!shares[numParties - 1]) {
        freeBIGNUMVector(shares);
        BN_free(sum);
        throw std::runtime_error("Failed to allocate BIGNUM for secret share s5");
    }
    BN_mod_sub(shares[numParties - 1], x, sum, q, ctx);

    secretShares = shares;

    BIGNUM* verify = BN_new();
    BN_zero(verify);
    for (size_t i = 0; i < numParties; ++i) {
        BN_mod_add(verify, verify, secretShares[i], q, ctx);
    }
    if (BN_cmp(verify, x) != 0) {
        freeBIGNUMVector(shares);
        BN_free(verify);
        throw std::runtime_error("Secret shares do not sum up to the original secret x");
    }
    BN_free(verify);
}



void ThresholdElGamalEncryption::BIGNUMToBytes(const BIGNUM* bn, std::vector<uint8_t>& output, size_t expectedSize) const {

    int numBytes = BN_num_bytes(bn);

    output.assign(expectedSize, 0);

    BN_bn2bin(bn, output.data() + (expectedSize - numBytes));
}


void ThresholdElGamalEncryption::sequentialDecrypt(const std::pair<BIGNUM*, BIGNUM*>& ciphertext, std::vector<uint8_t>& plaintext, size_t plaintextSize) const {
    if (secretShares.size() < threshold) {
        throw std::runtime_error("Not enough secret shares for decryption");
    }

    BIGNUM* current_c2 = BN_dup(ciphertext.second);
    if (!current_c2) {
        throw std::runtime_error("Failed to duplicate c2");
    }

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(current_c2);
        throw std::runtime_error("Failed to create BN_CTX");
    }

    for (size_t i = 0; i < threshold; ++i) {
        const BIGNUM* s_i = secretShares[i];

        // c1^{s_i} mod p
        BIGNUM* c1_s = BN_new();
        if (!c1_s) {
            BN_free(current_c2);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to allocate BIGNUM for c1^s_i");
        }

        if (BN_mod_exp(c1_s, ciphertext.first, s_i, p, ctx) != 1) {
            BN_free(c1_s);
            BN_free(current_c2);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to compute c1^s_i mod p");
        }

        //  (c1^{s_i})^{-1} mod p
        BIGNUM* c1_s_inv = BN_mod_inverse(NULL, c1_s, p, ctx);
        if (!c1_s_inv) {
            BN_free(c1_s);
            BN_free(current_c2);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to compute inverse of c1^s_i mod p");
        }

        //  c2 = current_c2 * (c1^{s_i})^{-1} mod p
        BIGNUM* new_c2 = BN_new();
        if (!new_c2) {
            BN_free(c1_s);
            BN_free(c1_s_inv);
            BN_free(current_c2);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to allocate BIGNUM for new c2");
        }

        if (BN_mod_mul(new_c2, current_c2, c1_s_inv, p, ctx) != 1) {
            BN_free(c1_s);
            BN_free(c1_s_inv);
            BN_free(current_c2);
            BN_free(new_c2);
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to compute new c2 during decryption");
        }

        BN_free(current_c2);
        current_c2 = new_c2;

        BN_free(c1_s);
        BN_free(c1_s_inv);
    }

    BIGNUMToBytes(current_c2, plaintext, plaintextSize);

    BN_free(current_c2);
    BN_CTX_free(ctx);
}
