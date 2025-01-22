
#ifndef BIGNUM_TRANS_OPERATION_H
#define BIGNUM_TRANS_OPERATION_H

#include <openssl/bn.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cryptoTools/Common/Defines.h>

static int oberg_comm = 0;

using boost::asio::ip::tcp;

//Serialize a BIGNUM into a byte array
std::vector<uint8_t> serializeBIGNUM(BIGNUM* bn);

//Deserialize a byte array to BIGNUM
BIGNUM* deserializeBIGNUM(const uint8_t* data, size_t& offset);

std::vector<uint8_t> serializeBlocks(const std::vector<std::vector<osuCrypto::block>>& sw);

std::vector<std::vector<osuCrypto::block>> deserializeBlocks(const uint8_t* data, size_t& local_offset, size_t data_size);

std::vector<uint8_t> serializeVector(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& A);

void deserializeData(const uint8_t* data, size_t data_size,
                     std::vector<std::pair<BIGNUM*, BIGNUM*>>& data_out);

std::vector<uint8_t> serializeData(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& data);

void deserializeData(const uint8_t* data, size_t data_size,
                     std::vector<std::pair<BIGNUM*, BIGNUM*>>& A,
                     std::vector<std::vector<osuCrypto::block>>& sw);

void BIGNUM_server(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& data);
void BIGNUM_client(std::vector<std::pair<BIGNUM*, BIGNUM*>>& data_out);

void sw_client(std::vector<std::vector<osuCrypto::block>>& sw);
void sw_server(const std::vector<std::vector<osuCrypto::block>>& sw);

bool compareBIGNUMData(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& sent_data,
                       const std::vector<std::pair<BIGNUM*, BIGNUM*>>& received_data);

int betorg_count();

#endif
