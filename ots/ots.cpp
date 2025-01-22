//
// \file ots.cpp
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

#include "ots.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Session.h"

#include "libOTe/Base/SimplestOT.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "../common/constants.h"
#include "../common/psi_analytics_context.h"
#include "../Eval.h"



namespace ENCRYPTO {
    std::pair<std::vector<std::uint64_t>, std::vector<std::vector<std::uint64_t>>> ot_r_s(
            const std::vector<std::vector<std::uint64_t>> &sender_inputs,
            const std::vector<std::uint64_t> &recv_inputs, osuCrypto::cp::LocalAsyncSocket& ch0,
            osuCrypto::cp::LocalAsyncSocket& ch1) {

        //************************ot_sender********************************
        osuCrypto::PRNG prng1(osuCrypto::block(42532335, 334565));

        std::size_t sender_numOTs = sender_inputs.size();
        osuCrypto::KkrtNcoOtSender sender;
        std::vector<std::vector<std::uint64_t>> sender_outputs(sender_inputs.size());
        sender.configure(false, 40, 128);
        osuCrypto::u64 sender_baseCount = sender.getBaseOTCount();
        osuCrypto::SimplestOT sender_baseOTs;
        osuCrypto::BitVector choices(sender_baseCount);
        std::vector<osuCrypto::block> sender_baseRecv(sender_baseCount);
        choices.randomize(prng1);

        //************************ot_receiver********************************
        osuCrypto::PRNG prng0(osuCrypto::block(4253465, 3434565));

        std::vector<std::uint64_t> recv_outputs;
        recv_outputs.reserve(recv_inputs.size());
        std::size_t recv_numOTs = recv_inputs.size();
        osuCrypto::KkrtNcoOtReceiver recv;
        recv.configure(false, 40, symsecbits);
        osuCrypto::u64 recv_baseCount = recv.getBaseOTCount();
        std::vector<osuCrypto::block> recv_baseRecv(recv_baseCount);
        std::vector<std::array<osuCrypto::block, 2>> recv_baseSend(recv_baseCount);
        osuCrypto::SimplestOT recv_baseOTs;

        //************************ot_comm********************************
        auto p0 = recv_baseOTs.send(recv_baseSend, prng0, ch0);
        auto p1 = sender_baseOTs.receive(choices, sender_baseRecv, prng1, ch1);
        eval(p0, p1);


        //************************ot_sender********************************
        sender.setBaseOts(sender_baseRecv, choices);

        //************************ot_receiver********************************
        recv.setBaseOts(recv_baseSend);

        //************************ot_comm********************************
        auto p01 = recv.init(recv_numOTs, prng0, ch0);
        auto p11 = sender.init(sender_numOTs, prng1, ch1);
        eval(p01, p11);

        //************************ot_sender********************************
        std::vector<std::vector<osuCrypto::block>> sender_inputs_as_blocks(sender_numOTs), sender_outputs_as_blocks(
                sender_numOTs);
        for (auto i = 0ull; i < sender_numOTs; ++i) {
            sender_outputs_as_blocks.at(i).resize(sender_inputs.at(i).size());
            for (auto &var: sender_inputs.at(i)) {
                sender_inputs_as_blocks.at(i).push_back(osuCrypto::toBlock(var));
            }
        }

        //************************ot_receiver********************************
        std::vector<osuCrypto::block> recv_blocks(recv_numOTs), recv_encoding(recv_numOTs);

        for (auto i = 0ull; i < recv_inputs.size(); ++i) {
            recv_blocks.at(i) = osuCrypto::toBlock(recv_inputs[i]);
        }

        for (auto k = 0ull; k < recv_numOTs && k < recv_inputs.size(); ++k) {
            recv.encode(k, &recv_blocks.at(k),
                        reinterpret_cast<uint8_t *>(&recv_encoding.at(k)),
                        sizeof(osuCrypto::block));
        }

        //************************ot_comm********************************
        auto p02 = recv.sendCorrection(ch0, recv_numOTs);
        auto p12 = sender.recvCorrection(ch1, sender_numOTs);
        eval(p02, p12);

        //************************ot_sender********************************
        for (auto i = 0ull; i < sender_numOTs; ++i) {
            for (auto j = 0ull; j < sender_inputs_as_blocks.at(i).size(); ++j) {
                sender.encode(i, &sender_inputs_as_blocks.at(i).at(j),
                              &sender_outputs_as_blocks.at(i).at(j),
                              sizeof(osuCrypto::block));
            }
        }

        for (auto i = 0ull; i < sender_numOTs; ++i) {
            for (auto &encoding: sender_outputs_as_blocks.at(i)) {
                sender_outputs.at(i).push_back(reinterpret_cast<uint64_t *>(&encoding)[0] &= __61_bit_mask);
            }
        }


        //************************ot_receiver********************************
        for (auto k = 0ull; k < recv_numOTs; ++k) {
            // copy only part of the encoding
            recv_outputs.push_back(reinterpret_cast<uint64_t *>(&recv_encoding.at(k))[0] &= __61_bit_mask);
        }


        return std::make_pair(recv_outputs, sender_outputs);
    }
}