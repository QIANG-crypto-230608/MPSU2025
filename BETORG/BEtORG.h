
#ifndef BETORG_H
#define BETORG_H

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
#include "../OSN/OSN.h"


int beqt_thread(int party, int b, int l, int num_cmps, int port, uint64_t* input, uint8_t *res_shares);

class BETORG{
public:

    void base_ot(std::vector<std::array<osuCrypto::block, 2>>& sendMsg,
                 std::vector<osuCrypto::block>& recvMsg,
                 osuCrypto::BitVector& choices,
                 osuCrypto::cp::LocalAsyncSocket& ch0,
                 osuCrypto::cp::LocalAsyncSocket& ch1);

    BETORG(){};

    //return recv, send;
    std::pair<std::vector<oc::block>, std::vector<oc::block>> run_betorg(
            std::vector<oc::block> send_input,
            std::vector<oc::block> recv_input,
            osuCrypto::cp::LocalAsyncSocket& ch0,
            osuCrypto::cp::LocalAsyncSocket& ch1,
            int* comm_beqt);
};

#endif
