#ifndef OSN_H
#define OSN_H



#pragma once

#include <vector>
#include <string>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <atomic>
#include "benes.h"


class OSN
{
    size_t size;
    int ot_type;
    std::atomic<int> cpus;

    Benes benes;

    void rand_ot(std::vector<std::array<osuCrypto::block, 2>>& sendMsg,
                 std::vector<osuCrypto::block>& recvMsg,
                 osuCrypto::BitVector& choices, osuCrypto::cp::LocalAsyncSocket& ch0, osuCrypto::cp::LocalAsyncSocket& ch1);

    void silent_ot(std::vector<std::array<osuCrypto::block, 2>>& sendMsg,
                   std::vector<osuCrypto::block>& recvMsg,
                   osuCrypto::BitVector& choices, osuCrypto::cp::LocalAsyncSocket& ch0, osuCrypto::cp::LocalAsyncSocket& ch1);

    //return OSNReceiver, OSNSender
    //Input OSNReceiver_values, OSNSender_values, sock[0], sock[1];
    std::pair<std::vector<std::vector<osuCrypto::block>>, std::vector<std::array<osuCrypto::block, 2>>> gen_benes_osn(
            int recv_values,int send_values,
            osuCrypto::cp::LocalAsyncSocket& ch0,
            osuCrypto::cp::LocalAsyncSocket& ch1);


    void prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<oc::block>& src,
                            std::vector<std::array<std::array<osuCrypto::block, 2>, 2>>& ot_output,
                            std::vector<std::array<osuCrypto::block, 2>>& correction_blocks);

public:
    std::vector<int> dest;
    OSN(size_t size = 0, int ot_type = 0);
    void init(size_t size, int ot_type = 0, const std::string& osn_cache = "");

    //return OSNReceiver, OSNSender
    std::pair<std::vector<oc::block>, std::vector<oc::block>> run_osn(std::vector<oc::block> recv_inputs,
                                   osuCrypto::cp::LocalAsyncSocket& ch0,
                                   osuCrypto::cp::LocalAsyncSocket& ch1);

};




#endif
