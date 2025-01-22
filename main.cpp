#include "Party.h"
#include "ThresholdElGamalEncryption.h"
#include "EncryptedCuckooHashTable.h"
#include <iostream>
#include <cmath>
#include <openssl/bn.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "ots/ots.h"
#include "common/psi_analytics_context.h"
#include "common/psi_analytics.h"
#include "OSN/OSN.h"
#include "Eval.h"
#include "BETORG/BEtORG.h"
#include "BIGNUM_Trans_operation.h"
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <thread>
#include <libkern/OSByteOrder.h>

using namespace osuCrypto;

struct DecryptedData{
    unsigned  char hash[16];
    uint64_t element;
};

bool verifyHash(const DecryptedData& data)
{
    unsigned char computed_hash_full[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned  char*>(&data.element), sizeof(uint64_t), computed_hash_full);

    unsigned char computed_hash[16];
    memcpy(computed_hash, computed_hash_full, 16);

    return (memcmp(data.hash, computed_hash, 16) == 0);
}


// Serialization function: converts a uint64_t to std::vector<uint8_t> (big-endian)
std::vector<uint8_t> serializeUint64(const std::uint64_t& input) {
    std::vector<uint8_t> output(8, 0);
    for (int i = 7; i >= 0; --i) {
        output[7 - i] = (input >> (i * 8)) & 0xFF;
    }
    return output;
}


// Deserialization function: converts an std::vector<uint8_t> (8 bytes) to uint64_t (big-endian)
std::uint64_t deserializeUint64(const std::vector<uint8_t>& input) {
    if (input.size() != 8) {
        throw std::runtime_error("Invalid input size for deserialization");
    }

    std::uint64_t num = 0;
    for (size_t i = 0; i < 8; ++i) {
        num = (num << 8) | input[i];
    }
    return num;
}

size_t communicationCost = 0;

int main() {
    size_t t = 3;
    size_t n = pow(2, 12);
    double epsilon = 1.27;
    size_t numParties = t;
    size_t threshold = t;

    PRNG prng(sysRandomSeed());

    std::vector<Party> parties;

    for (size_t i = 0; i < t; ++i) {
        parties.emplace_back(n, prng, epsilon, t, i);
    }

    auto start = std::chrono::high_resolution_clock::now();

    for(size_t i = 0; i < t; ++i){
        parties[i].partyIndex = i;
    }

    for(size_t i = 1; i < t; ++i){
        parties[i].r.resize(i);
        for(auto & j : parties[i].r){
            j.resize(std::ceil(epsilon * n));
        }
    }


    for(size_t i = 0; i < t - 1; i++){
        parties[i].w.resize(t - i - 1);
        for(auto & j : parties[i].w){
            j.resize(std::ceil(epsilon * n));
        }
    }
    for(size_t i = 1; i < t; ++i){
        parties[i].s_2.resize(i);
        for(auto & j : parties[i].s_2){
            j.resize(std::ceil(epsilon * n));
        }
    }
    for(size_t i = 0; i < t - 1; i++){
        parties[i].s_1.resize(t - i - 1);
        for(auto & j : parties[i].s_1){
            j.resize(std::ceil(epsilon * n));
        }
    }

    for(size_t i = 0; i < t - 1; i++){
        parties[i].a.resize(std::ceil(epsilon * n) * (i + 1));
        for(size_t j = 0; j < std::ceil(epsilon * n) * (i + 1); j++){
            parties[i].a[j] = osuCrypto::ZeroBlock;
        }
    }

    for(size_t i = 1; i < t; i++){
        parties[i].b.resize(std::ceil(epsilon * n) * i);
        for(size_t j = 0; j < std::ceil(epsilon * n) * i; j++){
            parties[i].b[j] = osuCrypto::ZeroBlock;
        }
    }
    parties[0].b.resize(std::ceil(epsilon * n));

    for(size_t i = 0; i < t - 1; i++){
        parties[i].sw.resize(t - i - 1);
        for(size_t j = 0; j < parties[i].sw.size(); j++){
                parties[i].sw[j].resize(std::ceil(epsilon * n));
        }
    }

    for(size_t i = 0; i < t - 1; i++){
        parties[i].com_sw.resize(t - i - 1);
        for(size_t j = 0; j < parties[i].com_sw.size(); j++){
            parties[i].com_sw[j].resize(std::ceil(epsilon * n) * (i + 1));
        }
    }

    for(size_t i = 0; i < t; i++){
        if(i == t - 1)
            parties[i].A.resize(std::ceil(epsilon * n) * i);
        else
            parties[i].A.resize(std::ceil(epsilon * n) * (i+1));

        BIGNUM* first = BN_new();
        BIGNUM * second  = BN_new();
        BN_zero(first);
        BN_zero(second);

        for(size_t j = 0; j < parties[i].A.size(); j++){
            parties[i].A[j] = std::make_pair(first, second);
        }
    }



    ENCRYPTO::PsiAnalyticsContext context;
    context.port = 8888; context.bitlen = 61; context.neles = n; context.nbins = static_cast<uint64_t>(n * 1.27f);
    context.nfuns = 3; context.epsilon = 1.27f; context.address = "127.0.0.1";
    context.fbins = static_cast<uint64_t>(std::ceil(context.epsilon * context.neles * context.nfuns));
    //when neles >=2^20, there is an error in bufferlength = (uint64_t)ceil(context.fbins - 3 * context.nbins);
    // osuCrypto::PRNG prngo(osuCrypto::sysRandomSeed(), bufferlength);
    // because bufferlength =0, the reason is the loss of decimal places. So we change here, and change 1.27f to 1.27

    if(n == pow(2, 12)){
        context.polynomialsize = 975;
        context.polynomialbytelength = context.polynomialsize * sizeof(uint64_t);
        context.nmegabins = 16;
    }

    if(n == pow(2, 16)){
        context.polynomialsize = 1021;
        context.polynomialbytelength = context.polynomialsize * sizeof(uint64_t);
        context.nmegabins = 248;
    }

    if(n == pow(2, 20)){
        context.polynomialsize = 1024;
        context.polynomialbytelength = context.polynomialsize * sizeof(uint64_t);
        context.nmegabins = 4002;
    }


    for(auto& party : parties){
        party.cuckoo_table.SetNumOfHashFunctions(3);
        party.cuckoo_table.Insert(party.X);
        party.cuckoo_table.MapElements();

        if (party.cuckoo_table.GetStashSize() > 0u)
            std::cerr << "[Error] Stash of size " << party.cuckoo_table.GetStashSize() << " occured\n";
        party.cuckoo_table_v = party.cuckoo_table.AsRawVector();
    }

    for(auto& party : parties){
        party.simple_table.SetNumOfHashFunctions(3);
        party.simple_table.Insert(party.X);
        party.simple_table.MapElements();
        party.simple_table_v = party.simple_table.AsRaw2DVector();
    }

    ThresholdElGamalEncryption thresholdEncryption(numParties, threshold);
    thresholdEncryption.generateKeys();

    const BIGNUM* publicKeyBN = thresholdEncryption.getPublicKey();
    const BIGNUM* pBN = thresholdEncryption.getP();
    const BIGNUM* gBN = thresholdEncryption.getG();

    for (size_t i = 0; i < t; ++i) {
        parties[i].publicKey = BN_dup(thresholdEncryption.getPublicKey());
        parties[i].secretShare = BN_dup(thresholdEncryption.getSecretShare(i));
        parties[i].p = BN_dup(thresholdEncryption.getP());
        parties[i].g = BN_dup(thresholdEncryption.getG());
        parties[i].partyIndex = i;
    }

    uint64_t zeroNum = 1;
    for(size_t i = 0; i < t; ++i){
        for(size_t j = 0; j < static_cast<std::size_t>(std::ceil(epsilon * n)); ++j){
            std::vector<uint8_t> concatenatedValue = concatenateHashAndElement(parties[i].cuckoo_table_v[j]);
            std::pair<BIGNUM*, BIGNUM*> encryptedValue;
            thresholdEncryption.encrypt(concatenatedValue,encryptedValue);
            parties[i].encrypted_cuckoo_table_v.emplace_back(encryptedValue);
            char* c1Hex = BN_bn2hex(parties[i].encrypted_cuckoo_table_v[j].first);
            char* c2Hex = BN_bn2hex(parties[i].encrypted_cuckoo_table_v[j].second);
        }

        if(i > 0){
            uint64_t zeroValue = 1;
            std::vector<uint8_t> plaintextZeroBytes = serializeUint64(zeroValue);
            for(size_t j = 0; j < std::ceil(epsilon * n) * i; ++j){
                std::pair<BIGNUM*, BIGNUM*> encryptedZeroValue;
                thresholdEncryption.encrypt(plaintextZeroBytes, encryptedZeroValue);
                parties[i].encrypted_zero_table_v.emplace_back(encryptedZeroValue);
            }
        }

    }


    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = (end - start)/t;
    std::cout << "Total time taken: " << elapsed.count() << " seconds." << std::endl;


    auto start1 = std::chrono::high_resolution_clock::now();
    //**************************Online Phase*********************************
    //**********************OPPRF step 1
    auto sock2 = cp::LocalAsyncSocket::makePair();
    for(int i = 0; i < t; i++){
        for(int j = i + 1; j < t; j++){
            auto [W, R] = ENCRYPTO::OPPRF(
                    parties[i].cuckoo_table_v,
                    parties[j].simple_table_v,
                    context, sock2[0], sock2[1]);
            for(int k = 0; k < W.size(); k++){
                parties[i].w[j-i-1][k] = osuCrypto::toBlock(W[k]);
            }

            for(int k = 0; k < R.size(); k++){
                parties[j].r[i][k] = osuCrypto::toBlock(R[k]);
            }
        }
    }

    communicationCost += sock2[0].bytesSent() + sock2[0].bytesReceived() + ENCRYPTO::opprf_getCount();

    //**********************PS step 2
    OSN osn;
    auto sock = cp::LocalAsyncSocket::makePair();
    osn.init(std::ceil(epsilon * n));
    for(int i = 0; i < t; i++){
        for(int j = i + 1; j < t; j++){
            auto [S2, S1] =
                    osn.run_osn(parties[j].r[i], sock[0], sock[1]);
            for(int k = 0; k < S1.size(); k++){
                parties[i].s_1[j-i-1][k] = S1[k];
            }
            for(int k = 0; k < S2.size(); k++){
                parties[j].s_2[i][k] = S1[k];
            }
        }
    }

    communicationCost += sock[1].bytesSent() + sock[1].bytesReceived();


    //**********************BEtORG +   step 3 (a) + (b)
    BETORG betorg;

    //construct sw
    for(size_t i = 0; i < t - 1; i++){
        for(size_t j = 0; j < parties[i].sw.size(); j++){
            for(size_t k = 0; k < parties[i].w[j].size(); k++) {
                parties[i].sw[j][k] = parties[i].w[j][k] ^ parties[i].s_1[j][k];
                parties[i].com_sw[j][k + std::ceil(epsilon * n) * i] = parties[i].sw[j][k];
            }
        }
    }

    for(size_t i = 0; i < t - 1; i++){
        for(size_t j = 0; j < parties[i].com_sw.size(); j++){
            for(size_t k = 0; k < (std::ceil(epsilon * n) * i); k++) {
                parties[i].com_sw[j][k] = ZeroBlock;
            }
        }
    }


    //combine s_2
    for(int i = 1; i < t; i++){
        for(const auto& vec : parties[i].s_2){
            parties[i].com_s_2.insert(parties[i].com_s_2.end(), vec.begin(), vec.end());
        }
    }


    auto sock_1 = cp::LocalAsyncSocket::makePair();
    for(int i = 0; i < t - 1; i++) {
        int beqt_comm = 0;
        auto [b, a] =
                betorg.run_betorg(parties[i].com_sw[0],
                                  parties[i + 1].com_s_2,
                                  sock_1[0], sock_1[1],
                                  &beqt_comm);

        communicationCost += sock_1[1].bytesSent() + sock_1[1].bytesReceived() + beqt_comm;

        for (int k = 0; k < a.size(); k++) {
            parties[i].a[k] = a[k];
        }
        for (int k = 0; k < b.size(); k++) {
            parties[i + 1].b[k] = b[k];
        }

        //Update com_sw
        for (int j = 0; j < parties[i].com_sw.size(); j++) {
            for (int k = 0; k < parties[i].com_sw[j].size(); k++) {
                parties[i].com_sw[j][k] = parties[i].com_sw[j][k] ^ parties[i].a[k];
            }
        }


        // Construct A
        for (int j = 0; j < parties[i].A.size(); j++){
            if((i == 0) || (j >= (std::ceil(epsilon * n) * i))){
                BIGNUM *first_xor = BN_new();
                BIGNUM *second_xor = BN_new();
                BN_copy(first_xor, parties[i].encrypted_cuckoo_table_v[j - (std::ceil(epsilon * n) * i)].first);
                BN_copy(second_xor, parties[i].encrypted_cuckoo_table_v[j - (std::ceil(epsilon * n) * i)].second);
                BIGNUM *xor_first_result = thresholdEncryption.xorBIGNUMWithBlock(first_xor, parties[i].a[j]);
                BIGNUM *xor_second_result = thresholdEncryption.xorBIGNUMWithBlock(second_xor, parties[i].a[j]);
                parties[i].A[j].first = xor_first_result;
                parties[i].A[j].second = xor_second_result;
            }else{
                BIGNUM *first_xor = BN_new();
                BIGNUM *second_xor = BN_new();
                BN_copy(first_xor, parties[i].A[j].first);
                BN_copy(second_xor, parties[i].A[j].second);
                BIGNUM *xor_first_result = thresholdEncryption.xorBIGNUMWithBlock(first_xor, parties[i].a[j]);
                BIGNUM *xor_second_result = thresholdEncryption.xorBIGNUMWithBlock(second_xor, parties[i].a[j]);
                parties[i].A[j].first = BN_dup(xor_first_result);
                parties[i].A[j].second = BN_dup(xor_second_result);
            }
        }


        //Pi send A and sw to Pi+1

    //      std::cout << "P" << i << " sends A and sw to " << "P" << i+1 << std::endl;
            std::vector<std::vector<block>> tmp_sw(t - 2 - i);
            for (int j = 0; j < tmp_sw.size(); j++) {
                tmp_sw[j].resize(parties[i].com_sw[0].size());
                for (int k = 0; k < parties[i].com_sw[0].size(); k++) {
                    tmp_sw[j][k] = parties[i].com_sw[j + 1][k];
                }
            }

            if(i != t - 2){
                std::thread server_thread([&]() {
                    sw_server(tmp_sw);
                });

                std::thread client_thread([&]() {
                    std::vector<std::pair<BIGNUM *, BIGNUM *>> received_A;
                    std::vector<std::vector<block>> received_sw;
                    sw_client(received_sw);

                    for (int j = 0; j < received_sw.size(); j++) {
                        for (int k = 0; k < received_sw[j].size(); k++) {
                            parties[i + 1].com_sw[j][k] = received_sw[j][k] ^ parties[i + 1].b[k];
                        }
                    }
                });

                server_thread.join();
                client_thread.join();
            }


        std::thread bigserver_thread([&]() {
            BIGNUM_server(parties[i].A);
        });

        std::thread bigclient_thread([&]() {
            std::vector<std::pair<BIGNUM *, BIGNUM *>> received_A;
            BIGNUM_client(received_A);



            for (int j = 0; j < received_A.size(); j++) {
                BIGNUM *first_xor = BN_new();
                BIGNUM *second_xor = BN_new();
                BN_copy(first_xor, received_A[j].first);
                BN_copy(second_xor, received_A[j].second);
                BIGNUM *xor_first_result = thresholdEncryption.xorBIGNUMWithBlock(first_xor, parties[i + 1].b[j]);
                BIGNUM *xor_second_result = thresholdEncryption.xorBIGNUMWithBlock(second_xor, parties[i + 1].b[j]);
                std::pair<BIGNUM *, BIGNUM *> tmp;
                tmp.first = xor_first_result; tmp.second = xor_second_result;

                std::pair<BIGNUM *, BIGNUM *> result;
                thresholdEncryption.multiplyCiphertexts(tmp, parties[i + 1].encrypted_zero_table_v[j], result);
                parties[i+1].A[j].first = BN_dup(result.first);
                parties[i+1].A[j].second = BN_dup(result.second);
            }

        });
            bigserver_thread.join();
            bigclient_thread.join();
    }

    //Joint decryption
    //Pt->P0
//    std::cout << "P" << t-1 << "sends ciphertext to" << "P0\n" ;
    std::thread server_thread([&](){
        BIGNUM_server(parties[t - 1].A);
    });

    std::vector<std::pair<BIGNUM*, BIGNUM*>> shared_ciphertexts;
    std::thread client_thread([&](){
        BIGNUM_client(shared_ciphertexts);
    });
    server_thread.join();
    client_thread.join();


    for(int i = 0; i < t; i++){
        for(size_t j = 0; j < shared_ciphertexts.size(); j++){
            std::pair<BIGNUM *, BIGNUM *>& ciphertext = shared_ciphertexts[j];
            BIGNUM * current_c2 = BN_dup(ciphertext.second);

            if(!current_c2){
                throw std::runtime_error("Failed to duplicate c2");
            }

            const BIGNUM* s_i = thresholdEncryption.secretShares[i];

            BN_CTX* ctx = BN_CTX_new();
            if(!ctx){
                BN_free(current_c2);
                throw std::runtime_error("Failed to create BN_CTX");
            }

            BIGNUM* c1_s = BN_new();
            if(!c1_s){
                BN_free(current_c2);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to allocate c1_s");
            }

            if(BN_mod_exp(c1_s, ciphertext.first, s_i, thresholdEncryption.p, ctx) != 1){
                BN_free(c1_s);
                BN_free(current_c2);
                BN_CTX_free(ctx);
                throw std::runtime_error("Fialed to compute c1^s_i mod p");
            }

            BIGNUM * c1_s_inv = BN_mod_inverse(NULL, c1_s, thresholdEncryption.p, ctx);
            if(!c1_s_inv){
                BN_free(c1_s);
                BN_free(current_c2);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to compute inverse of c1^s_i mod p");
            }

            BIGNUM * new_c2 = BN_new();
            if (!new_c2) {
                BN_free(c1_s);
                BN_free(c1_s_inv);
                BN_free(current_c2);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to allocate new_c2");
            }

            if(BN_mod_mul(new_c2, current_c2, c1_s_inv, thresholdEncryption.p, ctx) != 1){
                BN_free(new_c2);
                BN_free(c1_s);
                BN_free(c1_s_inv);
                BN_free(current_c2);
                BN_CTX_free(ctx);
                throw std::runtime_error("Failed to compute new c2 during decryption");
            }

            BN_free(ciphertext.second);
            ciphertext.second = new_c2;

            BN_free(c1_s);
            BN_free(c1_s_inv);
            BN_free(current_c2);
            BN_CTX_free(ctx);
        }

        thresholdEncryption.shuffleCiphertext(shared_ciphertexts);

        if(i != t - 1){
            thresholdEncryption.shuffleCiphertext(shared_ciphertexts);
            std::thread server_thread([&](){
                BIGNUM_server(shared_ciphertexts);
            });


            std::thread client_thread([&](){
                BIGNUM_client(shared_ciphertexts);
            });
            server_thread.join();
            client_thread.join();
        }

    }


    //Convert jointly decrypted plaintext to uint64_t
    std::vector<DecryptedData> X_decrypted(shared_ciphertexts.size());
    for(int i = 0; i < shared_ciphertexts.size(); i++){
        std::pair<BIGNUM*, BIGNUM*> ciphertext = shared_ciphertexts[i];
        DecryptedData decryptedData;

        int numBytes = BN_num_bytes(ciphertext.second);
        std::vector<uint8_t> decryptedBytes(numBytes);
        BN_bn2bin(ciphertext.second, decryptedBytes.data());

        size_t hashSize = 16;
        if(numBytes < hashSize){
            std::vector<uint8_t> hashBytes(16,0);
            memcpy(hashBytes.data(), decryptedBytes.data(), numBytes);
            std::copy(hashBytes.begin(), hashBytes.begin() + 16, decryptedData.hash);
            decryptedData.element = 0;
        }else{
            std::copy(decryptedBytes.begin(), decryptedBytes.begin() + 16, decryptedData.hash);
            size_t remainingSize = numBytes - 16;

            std::vector<uint8_t> elementBytes(8, 0);
            if(remainingSize > 0){
                size_t elementByteSize = std::min((size_t)8, remainingSize);
                memcpy(elementBytes.data() + (8 - elementByteSize),
                       decryptedBytes.data() + 16 + (remainingSize - elementByteSize),
                       elementByteSize);
            }
            uint64_t element_be;
            memcpy(&element_be, elementBytes.data(), sizeof(uint64_t));
            decryptedData.element = OSSwapBigToHostConstInt64(element_be);
        }

        X_decrypted[i] = decryptedData;
    }

    communicationCost += betorg_count();

    for (int i = 0; i < (int)X_decrypted.size(); i++) {
        unsigned char full_hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(&X_decrypted[i].element), sizeof(uint64_t), full_hash);

        unsigned  char truncated_hash[16];
        memcpy(truncated_hash, full_hash, 16);


        if (memcmp(truncated_hash, X_decrypted[i].hash, 16) == 0) {
            std::cout << "Index " << i << ": Hash matches! Element = " << X_decrypted[i].element << std::endl;

            std::cout << "Hash: ";
            for (int j = 0; j < 16; j++) {
                printf("%02x", X_decrypted[i].hash[j]);
            }
            std::cout << std::endl;
        } else {
             std::cout << "Index " << i << ": Hash does not match." << std::endl;
        }
    }

    auto end1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed1 = end1 - start1;
    std::cout << "Total time taken: " << elapsed1.count() << " seconds." << std::endl;
    std::cout << "Total communication cost: " << (communicationCost / (1024 * 1024)) << " MB." << std::endl;


    return 0;
}
