//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
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

#include "psi_analytics.h"

#include "ENCRYPTO_utils/crypto/crypto.h"
#include "ENCRYPTO_utils/parse_options.h"
#include "ABY/aby/abyparty.h"
#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "ABY/sharing/boolsharing.h"
#include "ABY/sharing/sharing.h"

#include "../ots/ots.h"
#include "../polynomials/Poly.h"

#include "../HashingTables/common/hash_table_entry.h"
#include "../HashingTables/common/hashing.h"
#include "../HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "../HashingTables/simple_hashing/simple_hashing.h"
#include "psi_analytics_context.h"

#include <cryptoTools/Crypto/PRNG.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <ratio>
#include <unordered_set>
#include <unordered_map>
#include <cmath>
#include <openssl/sha.h>
#include <boost/asio.hpp>
//#include "table_opprf.h"


//struct hashlocmp
//{
//    int bin;
//    int index;
//};
//
//std::vector<uint64_t> server_content_of_bins;
//std::vector<uint64_t> client_content_of_bins;




namespace ENCRYPTO {


    std::pair<std::vector<uint64_t>, std::vector<uint64_t>> OPPRF(
            const std::vector<uint64_t>& recv_cuckoo_table_v,
            const std::vector<std::vector<uint64_t>>& sender_simple_table_v, PsiAnalyticsContext& context, osuCrypto::cp::LocalAsyncSocket& ch0,
            osuCrypto::cp::LocalAsyncSocket& ch1){

        //************************OPPRF_comm********************************
        auto [client_masks_with_dummies, server_masks] = ENCRYPTO::ot_r_s(
                sender_simple_table_v,
                recv_cuckoo_table_v, ch0, ch1);

        //************************OPPRF_client********************************
        const auto client_nbinsinmegabin = ceil_divide(context.nbins, context.nmegabins);
        std::vector<std::vector<ZpMersenneLongElement>> client_polynomials(context.nmegabins);
        std::vector<ZpMersenneLongElement> A(context.nbins), B(context.nbins);
        for(auto &polynomial : client_polynomials){
            polynomial.resize(context.polynomialsize);
        }

        for(auto i = 0ull; i < A.size(); ++i){
            A.at(i).elem = client_masks_with_dummies.at(i);
        }

        std::vector<uint8_t> poly_rcv_buffer(context.nmegabins * context.polynomialbytelength, 0);

        //************************OPPRF_server********************************
        std::vector<uint64_t> server_polynomials(context.nmegabins * context.polynomialsize, 0);
        std::vector<uint64_t>  server_content_of_bins(context.nbins);

        std::random_device urandom("/dev/urandom");
        std::uniform_int_distribution<uint64_t> dist(0, (1ull << context.maxbitlen) - 1);  // [0,2^elebitlen)


        // generate random numbers to use for mapping the polynomial to
        std::generate(server_content_of_bins.begin(), server_content_of_bins.end(),
                      [&](){return dist(urandom);});
        {
            auto tmp = server_content_of_bins;
            std::sort(tmp.begin(), tmp.end());
            auto last = std::unique(tmp.begin(), tmp.end());
            tmp.erase(last, tmp.end());
            assert(tmp.size() == server_content_of_bins.size());
        }

        InterpolatePolynomials(server_polynomials, server_content_of_bins, server_masks, context);

        const uint8_t* server_send_buffer = reinterpret_cast<const uint8_t *>(server_polynomials.data());
        using boost::asio::ip::tcp;

        boost::asio::io_service  io_Service_server;
        boost::asio::io_service  io_Service_client;

        std::thread server_thread([&](){
            try{
                tcp::acceptor  acceptor(io_Service_server, tcp::endpoint(tcp::v4(), 9999));
                tcp::socket server_socket(io_Service_server);
                acceptor.accept(server_socket);

                size_t bytes_read = 0;
                while(bytes_read < context.nmegabins * context.polynomialbytelength){
                    bytes_read += server_socket.read_some(
                            boost::asio::buffer(poly_rcv_buffer.data()+bytes_read,
                                                context.nmegabins * context.polynomialbytelength - bytes_read));
                }

            } catch (std::exception& e){
            }
        });

        std::thread client_thread([&](){
            try{
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                tcp::socket client_socket(io_Service_client);
                tcp::resolver resolver(io_Service_client);
                boost::asio::connect(client_socket, resolver.resolve({"127.0.0.1", "9999"}));

                size_t bytes_sent = 0;
                while (bytes_sent < context.nmegabins * context.polynomialbytelength) {
                    bytes_sent += client_socket.write_some(
                            boost::asio::buffer(server_send_buffer + bytes_sent,
                                                context.nmegabins * context.polynomialbytelength - bytes_sent));
                }
                comm_OPPRF_extra += bytes_sent;
            }catch (std::exception& e) {
                std::cerr << "[Client] Exception: " << e.what() << std::endl;
            }
        });

        server_thread.join();
        client_thread.join();

        //************************OPPRF_client********************************
        for(auto poly_i = 0ull; poly_i < client_polynomials.size(); ++poly_i){
            for(auto coeff_i = 0ull; coeff_i < context.polynomialsize; ++coeff_i){
                client_polynomials.at(poly_i).at(coeff_i).elem =
                        (reinterpret_cast<uint64_t *>(poly_rcv_buffer.data()))[poly_i * context.polynomialsize + coeff_i];
            }
        }

        for(auto i = 0ull; i < A.size(); ++i){
            std::size_t p = i / client_nbinsinmegabin;
            Poly::evalMersenne(B.at(i), client_polynomials.at(p), A.at(i));
        }

        std::vector<uint64_t> raw_bin_result;
        raw_bin_result.reserve(A.size());
        for(auto i = 0ull; i < A.size(); ++i){
            raw_bin_result.push_back(A[i].elem ^ B[i].elem);
        }

        return std::make_pair(raw_bin_result, server_content_of_bins); //Client, Server
    }



void InterpolatePolynomials(std::vector<uint64_t> &polynomials,
                            std::vector<uint64_t> &content_of_bins,
                            const std::vector<std::vector<uint64_t>> &masks,
                            PsiAnalyticsContext &context) {
  std::size_t nbins = masks.size();
  std::size_t masks_offset = 0;
  std::size_t nbinsinmegabin = ceil_divide(nbins, context.nmegabins);

  for (auto mega_bin_i = 0ull; mega_bin_i < context.nmegabins; ++mega_bin_i) {
    auto polynomial = polynomials.begin() + context.polynomialsize * mega_bin_i;
    auto bin = content_of_bins.begin() + nbinsinmegabin * mega_bin_i;
    auto masks_in_bin = masks.begin() + nbinsinmegabin * mega_bin_i;

    if ((masks_offset + nbinsinmegabin) > masks.size()) {
      auto overflow = (masks_offset + nbinsinmegabin) % masks.size();
      nbinsinmegabin -= overflow;
    }

    InterpolatePolynomialsPaddedWithDummies(polynomial, bin, masks_in_bin, nbinsinmegabin, context);
    masks_offset += nbinsinmegabin;
  }

  assert(masks_offset == masks.size());
}

void InterpolatePolynomialsPaddedWithDummies(
    std::vector<uint64_t>::iterator polynomial_offset,
    std::vector<uint64_t>::const_iterator random_value_in_bin,
    std::vector<std::vector<uint64_t>>::const_iterator masks_for_elems_in_bin,
    std::size_t nbins_in_megabin, PsiAnalyticsContext &context) {
  std::uniform_int_distribution<std::uint64_t> dist(0,
                                                    (1ull << context.maxbitlen) - 1);  // [0,2^61)
  std::random_device urandom("/dev/urandom");
  auto my_rand = [&urandom, &dist]() { return dist(urandom); };

  std::vector<ZpMersenneLongElement> X(context.polynomialsize), Y(context.polynomialsize),
      coeff(context.polynomialsize);

  for (auto i = 0ull, bin_counter = 0ull; i < context.polynomialsize;) {
    if (bin_counter < nbins_in_megabin) {
      if ((*masks_for_elems_in_bin).size() > 0) {
        for (auto &mask : *masks_for_elems_in_bin) {
          X.at(i).elem = mask & __61_bit_mask;
          Y.at(i).elem = X.at(i).elem ^ *random_value_in_bin;
          ++i;
        }
      }
      ++masks_for_elems_in_bin;
      ++random_value_in_bin;  // proceed to the next bin (iterator)
      ++bin_counter;
    } else {  // generate dummy elements for polynomial interpolation
      X.at(i).elem = my_rand();
      Y.at(i).elem = my_rand();
      ++i;
    }
  }

  Poly::interpolateMersenne(coeff, X, Y);

  auto coefficient = coeff.begin();
  for (auto i = 0ull; i < coeff.size(); ++i, ++polynomial_offset, ++coefficient) {
    *polynomial_offset = (*coefficient).elem;
  }
}

std::unique_ptr<CSocket> EstablishConnection(const std::string &address, uint16_t port,
                                             e_role role) {
  std::unique_ptr<CSocket> socket;
  if (role == SERVER) {
    socket = Listen(address.c_str(), port);
  } else {
    socket = Connect(address.c_str(), port);
  }
  assert(socket);
  return socket;
}

    int opprf_getCount() {
        return comm_OPPRF_extra;
    }


}
