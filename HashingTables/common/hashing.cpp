//
// \file hashing.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
// \copyright The MIT License. Copyright 2019
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include "hashing.h"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstdint>
#include <cstring>
#include <algorithm>

namespace ENCRYPTO {

bool HashingTable::MapElements() {
  AllocateTable();
  MapElementsToTable();
  mapped_ = true;
  return true;
}

bool HashingTable::AllocateLUTs() {
  luts_.resize(num_of_hash_functions_);
  for (auto& luts : luts_) {
    luts.resize(num_of_luts_);
    for (auto& entry : luts) {
      entry.resize(num_of_tables_in_lut_);
    }
  }
  return true;
}

bool HashingTable::GenerateLUTs() {
  for (auto i = 0ull; i < num_of_hash_functions_; ++i) {
    for (auto j = 0ull; j < num_of_luts_; ++j) {
      for (auto k = 0ull; k < num_of_tables_in_lut_; k++) {
        luts_.at(i).at(j).at(k) = generator_();
      }
    }
  }

  return true;
}

std::vector<std::uint64_t> HashingTable::HashToPosition(uint64_t element) const {
  std::vector<std::uint64_t> addresses;
  for (auto func_i = 0ull; func_i < num_of_hash_functions_; ++func_i) {
    std::uint64_t address = element;
    for (auto lut_i = 0ull; lut_i < num_of_luts_; ++lut_i) {
      std::size_t lut_id = ((address >> (lut_i * elem_byte_length_ / num_of_luts_)) & 0x000000FFu);
      lut_id %= num_of_tables_in_lut_;
      address ^= luts_.at(func_i).at(lut_i).at(lut_id);
    }
    addresses.push_back(address);
  }
  return addresses;
}

//std::uint64_t HashingTable::ElementToHash(std::uint64_t element) {
//  SHA_CTX ctx;
//  unsigned char hash[SHA_DIGEST_LENGTH];
//
//  SHA1_Init(&ctx);
//  SHA1_Update(&ctx, reinterpret_cast<unsigned char*>(&element), sizeof(element));
//  SHA1_Final(hash, &ctx);
//
//  uint64_t result = 0;
//  std::copy(hash, hash + sizeof(result), reinterpret_cast<unsigned char*>(&result));
//
//  return result;
//}
//}

std::uint64_t HashingTable::ElementToHash(std::uint64_t element) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();  // 创建新的上下文
    unsigned char hash[EVP_MAX_MD_SIZE]; // 输出缓冲区，最大为 EVP_MAX_MD_SIZE 字节
    unsigned int hash_len = 0;           // 用于存储哈希长度

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // 初始化 SHA1 哈希计算
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // 更新哈希计算，添加数据
    if (EVP_DigestUpdate(ctx, &element, sizeof(element)) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // 完成哈希计算
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    // 释放上下文
    EVP_MD_CTX_free(ctx);

    // 将前 8 字节（64 位）转换为 uint64_t
    uint64_t result = 0;
    std::memcpy(&result, hash, std::min(hash_len, static_cast<unsigned int>(sizeof(result))));

    return result;
}
}