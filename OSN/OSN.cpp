#pragma once

#include "OSN.h"
#include "libOTe/Base/SimplestOT.h"
#include "cryptoTools/Common/BitVector.h"
#include <cryptoTools/Crypto/AES.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <iterator>
#include <cstring>
#include <iostream>
#include "../Eval.h"

using namespace std;
using namespace oc;
using namespace osuCrypto;


OSN::OSN(size_t size, int ot_type) : size(size), ot_type(ot_type) {}


//return OSNReceiver, OSNSender
std::pair<std::vector<oc::block>, std::vector<oc::block>> OSN::run_osn(std::vector<oc::block> recv_inputs,
                                                                  osuCrypto::cp::LocalAsyncSocket& ch0,
                                                                  osuCrypto::cp::LocalAsyncSocket& ch1)
{
    int values = size;
    //***************************Sender*****************************
    int send_N = int(ceil(log2(values)));
    int send_levels = 2 * send_N - 1;

    //***************************Comm*****************************
    auto[recv_ret_masks, send_ot_output] =
            gen_benes_osn(values, values, ch0, ch1);

    //***************************Receiver*****************************
    std::vector<block> recv_output_masks, recv_benes_input;
    for(int i = 0; i < values; i++){
        recv_ret_masks[i][0] = recv_ret_masks[i][0] ^ recv_inputs[i];
    }
    for(int i = 0; i < values; i++){
        recv_benes_input.push_back(recv_ret_masks[i][0]);
    }

    //***************************Sender*****************************
    std::vector<block> send_input_vec(values);

    //***************************Comm*****************************
    std::thread send_thread([&] (){
        macoro::sync_wait([&]()->macoro::task<>{
            co_await  ch1.send(recv_benes_input, macoro::stop_token{});
            co_return;
        }());
    });

    std::thread recv_thread([&](){
        macoro::sync_wait([&]()->macoro::task<>{
            co_await ch0.recv(send_input_vec, macoro::stop_token{});
            co_return;
        }());
    });

    send_thread.join();
    recv_thread.join();

    //***************************Receiver*****************************
    for(int i = 0; i < values; ++i){
        recv_output_masks.push_back(recv_ret_masks[i][1]);
    }

    //***************************Sender*****************************
    std::vector<std::vector<std::array<osuCrypto::block, 2>>> send_matrix_ot_output(
            send_levels, std::vector<std::array<osuCrypto::block, 2>>(values));

    int ctr = 0;
    for(int i = 0; i < send_levels; ++i){
        for(int j = 0; j < values / 2; ++j){
            send_matrix_ot_output[i][j] = send_ot_output[ctr++];
        }
    }

    benes.gen_benes_masked_evaluate(send_N, 0, 0, send_input_vec, send_matrix_ot_output);

    return std::make_pair(recv_output_masks, send_input_vec);
}


void OSN::rand_ot(std::vector<std::array<osuCrypto::block, 2>>& sendMsg,
                 std::vector<osuCrypto::block>& recvMsg,
                 osuCrypto::BitVector& choices, osuCrypto::cp::LocalAsyncSocket& ch0, osuCrypto::cp::LocalAsyncSocket& ch1)
{

    //***************************Receiver*****************************
    osuCrypto::PRNG prng1(osuCrypto::toBlock(4253233465ULL, 334565ULL));

    std::vector<osuCrypto::block> recv_baseRecv(128);
    osuCrypto::SimplestOT recv_baseOTs;
    osuCrypto::BitVector recv_baseChoice(128);
    recv_baseChoice.randomize(prng1);
    osuCrypto::IknpOtExtSender recv_sender;
    recv_sender.setBaseOts(recv_baseRecv, recv_baseChoice);


    //***************************Sender*****************************
    osuCrypto::PRNG prng0(osuCrypto::toBlock(4253465ULL, 23987045ULL));
    osuCrypto::u64 send_numOTs = choices.size();
    std::vector<osuCrypto::block> send_baseRecv(128);
    std::vector<std::array<osuCrypto::block, 2>> send_baseSend(128);
    osuCrypto::BitVector send_baseChoice(128);

    prng0.get((osuCrypto::u8*)send_baseSend.data()->data(),
              sizeof(osuCrypto::block) * 2 * send_baseSend.size());

    osuCrypto::SimplestOT send_baseOTs;
    osuCrypto::IknpOtExtReceiver send_recv;
    send_recv.setBaseOts(send_baseSend);

    //***************************Comm*****************************
    auto p0 = send_baseOTs.send(send_baseSend, prng0, ch0);
    auto p1 = recv_baseOTs.receive(recv_baseChoice, recv_baseRecv, prng1, ch1);
    eval(p0, p1);

    //***************************Comm*****************************
    auto p0_ = recv_sender.send(sendMsg, prng1, ch1);
    auto p1_ = send_recv.receive(choices, recvMsg, prng0, ch0);
    eval(p0_,p1_);


}

void OSN::silent_ot(std::vector<std::array<osuCrypto::block, 2>>& sendMsg,
                   std::vector<osuCrypto::block>& recvMsg,
                   osuCrypto::BitVector& choices, osuCrypto::cp::LocalAsyncSocket& ch0, osuCrypto::cp::LocalAsyncSocket& ch1)
{
    //***************************Receiver*****************************
    osuCrypto::PRNG prng1(osuCrypto::toBlock(4253233465ULL, 334565ULL));
    osuCrypto::u64 recv_numOTs = sendMsg.size();
    osuCrypto::SilentOtExtSender recv_sender;
    recv_sender.configure(recv_numOTs,2,1);

    //***************************Sender*****************************
    osuCrypto::PRNG prng0(osuCrypto::toBlock(4253465ULL, 23987045ULL));
    osuCrypto::u64 send_numOTs = choices.size();
    osuCrypto::SilentOtExtReceiver send_recv;
    send_recv.configure(send_numOTs, 2, 1);

    //***************************Comm*****************************
    auto p0 = recv_sender.silentSend(sendMsg, prng1, ch1);
    auto p1 = send_recv.silentReceive(choices, recvMsg, prng0, ch0);
    eval(p0,p1);
}

//return OSNReceiver, OSNSender
//Input OSNReceiver_values, OSNSender_values, sock[0], sock[1];
std::pair<std::vector<std::vector<osuCrypto::block>>, std::vector<std::array<osuCrypto::block, 2>>> OSN::gen_benes_osn(
        int recv_values,int send_values,
        osuCrypto::cp::LocalAsyncSocket& ch0,
        osuCrypto::cp::LocalAsyncSocket& ch1)
{
    //***************************Receiver*****************************
    int recv_N = int(ceil(log2(recv_values)));
    int recv_levels = 2 * recv_N - 1;
    int recv_swithces = recv_levels * (recv_values / 2);
    block recv_temp;
    std::vector<block> recv_masks(recv_values);
    std::vector<std::vector<block>> recv_ret_masks(recv_values);

    osuCrypto::PRNG prng(osuCrypto::toBlock(4253233465ULL, 334565ULL));

    for(int j = 0; j < recv_values; j++){
        //sample the input masks randomly
        recv_temp = prng.get<block>();
        recv_masks[j] = recv_temp;
        recv_ret_masks[j].push_back(recv_temp);
    }

    std::vector<std::array<std::array<osuCrypto::block, 2>, 2>> recv_ot_messages(recv_swithces);

    //***************************Sender*****************************
    benes.initialize(send_values, recv_levels);
    osuCrypto::BitVector send_switches = benes.return_gen_benes_switches(send_values);
    std::vector<std::array<osuCrypto::block, 2>> send_recvMsg(send_switches.size());
    std::vector<std::array<osuCrypto::block, 2>> send_recvCorr(send_switches.size());

    if(ot_type == 0){
        //***************************Receiver*****************************
        std::vector<std::array<osuCrypto::block, 2>> recv_tmp_messages(recv_swithces);
        osuCrypto::BitVector recv_bit_correction(recv_swithces);

        //***************************Sender*****************************
        std::vector<osuCrypto::block> send_tmpMsg(send_switches.size());
        osuCrypto::BitVector send_choices(send_switches.size());

        //***************************Comm*****************************
        silent_ot(recv_tmp_messages, send_tmpMsg, send_choices, ch0, ch1); //sample random ot blocks

        //***************************Sender*****************************
        AES send_aes(ZeroBlock);

        for(auto i = 0; i < send_recvMsg.size(); i++) {
            send_recvMsg[i] = {send_tmpMsg[i], send_aes.ecbEncBlock(send_tmpMsg[i])};
        }
        osuCrypto::BitVector send_bit_correction = send_switches ^ send_choices;

        //***************************Comm*****************************
        std::thread send_thread([&] (){
            macoro::sync_wait([&]()->macoro::task<>{
                co_await  ch0.send(send_bit_correction, macoro::stop_token{});
                co_return;
            }());
        });

        std::thread recv_thread([&](){
            macoro::sync_wait([&]()->macoro::task<>{
               co_await ch1.recv(recv_bit_correction, macoro::stop_token{});
               co_return;
            }());
        });

        send_thread.join();
        recv_thread.join();

        //***************************Receiver*****************************
        osuCrypto::block recv_tmp;
        for(int k = 0; k < recv_tmp_messages.size(); k++){
            if(recv_bit_correction[k] == 1){
                recv_tmp = recv_tmp_messages[k][0];
                recv_tmp_messages[k][0] = recv_tmp_messages[k][1];
                recv_tmp_messages[k][1] = recv_tmp;
            }
        }

        AES recv_aes(ZeroBlock);

        for(auto i = 0; i < recv_ot_messages.size(); i++){
            recv_ot_messages[i][0] = {recv_tmp_messages[i][0], recv_aes.ecbEncBlock(recv_tmp_messages[i][0])};
            recv_ot_messages[i][1] = {recv_tmp_messages[i][1], recv_aes.ecbEncBlock(recv_tmp_messages[i][1])};
        }
    }else {
        //***************************Receiver*****************************
        std::vector<std::array<osuCrypto::block, 2>> recv_tmp_messages(recv_swithces);

        //***************************Sender*****************************
        std::vector<osuCrypto::block> send_tmpMsg(send_switches.size());

        //***************************Comm*****************************
        rand_ot(recv_tmp_messages, send_tmpMsg, send_switches, ch0, ch1);

        //***************************Receiver*****************************
        AES recv_aes(ZeroBlock);
        for (auto i = 0; i < recv_ot_messages.size(); i++) {
            recv_ot_messages[i][0] = {recv_tmp_messages[i][0], recv_aes.ecbEncBlock(recv_tmp_messages[i][0])};
            recv_ot_messages[i][1] = {recv_tmp_messages[i][1], recv_aes.ecbEncBlock(recv_tmp_messages[i][1])};
        }

        //***************************Sender*****************************
        AES send_aes(ZeroBlock);
        for (auto i = 0; i < send_recvMsg.size(); i++) {
            send_recvMsg[i] = {send_tmpMsg[i], send_aes.ecbEncBlock(send_tmpMsg[i])};
        }

    }
    //***************************Receiver*****************************
    cpus.store(1); //thread num;
    std::vector<std::array<osuCrypto::block, 2>> recv_correction_blocks(recv_swithces);
    prepare_correction(recv_N, recv_values, 0, 0, recv_masks,
                       recv_ot_messages, recv_correction_blocks);

    //***************************Comm*****************************
    std::thread send_thread_1([&] (){
        macoro::sync_wait([&]()->macoro::task<>{
            co_await  ch1.send(recv_correction_blocks, macoro::stop_token{});
            co_return;
        }());
    });

    std::thread recv_thread_1([&](){
        macoro::sync_wait([&]()->macoro::task<>{
            co_await ch0.recv(send_recvCorr, macoro::stop_token{});
            co_return;
        }());
    });

    send_thread_1.join();
    recv_thread_1.join();

    //***************************Receiver*****************************
    for(int i = 0; i < recv_values; i++){
        recv_ret_masks[i].push_back(recv_masks[i]);
    }

    //***************************Sender*****************************
    block send_temp_msg[2], send_temp_corr[2];
    for(int i = 0; i < send_recvMsg.size(); i++){
        if(send_switches[i] == 1){
            send_temp_msg[0] = send_recvCorr[i][0] ^ send_recvMsg[i][0];
            send_temp_msg[1] = send_recvCorr[i][1] ^ send_recvMsg[i][1];
            send_recvMsg[i] = {send_temp_msg[0], send_temp_msg[1]};
        }
    }

    return std::make_pair(recv_ret_masks, send_recvMsg);
}


void OSN::init(size_t size, int ot_type, const std::string& osn_cache)
{
    this->size = size;
    this->ot_type = ot_type;

    int values = size;
    int N = int(ceil(log2(values)));
    int levels = 2 * N - 1;

    dest.resize(size);
    benes.initialize(values, levels);

    std::vector<int> src(values);
    for (int i = 0; i < src.size(); ++i)
        src[i] = dest[i] = i;

    osuCrypto::block seed = osuCrypto::toBlock((uint64_t)4253233465ULL, (uint64_t)334565ULL);
    osuCrypto::PRNG prng(seed);
//    osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235)); // we need to modify this seed

    for (int i = size - 1; i > 0; i--)
    {
        int loc = prng.get<uint64_t>() % (i + 1); //  pick random location in the array
        std::swap(dest[i], dest[loc]);
    }
    if (osn_cache != "")
    {
        string file = osn_cache + "_" + to_string(size);
        if (!benes.load(file))
        {
            cout << "OSNSender is generating osn cache!" << endl;
            benes.gen_benes_route(N, 0, 0, src, dest);
            benes.dump(file);
        }
        else
        {
            cout << "OSNSender is using osn cache!" << endl;
        }
    }
    else
    {
        benes.gen_benes_route(N, 0, 0, src, dest);
    }
}



void OSN::prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<oc::block>& src,
                                     std::vector<std::array<std::array<osuCrypto::block, 2>, 2>>& ot_output,
                                     std::vector<std::array<osuCrypto::block, 2>>& correction_blocks)
{
    // ot message M0 = m0 ^ w0 || m1 ^ w1
    //  for each switch: top wire m0 w0 - bottom wires m1, w1
    //  M1 = m0 ^ w1 || m1 ^ w0
    int levels = 2 * n - 1, base_idx;
    int values = src.size();
    std::vector<block> bottom1;
    std::vector<block> top1;

    block m0, m1, w0, w1, M0[2], M1[2], corr_mesg[2];
    std::array<oc::block, 2> corr_block, temp_block;

    if (values == 2)
    {
        if (n == 1)
        {
            base_idx = lvl_p * (Val / 2) + perm_idx;
            m0 = src[0];
            m1 = src[1];
            temp_block = ot_output[base_idx][0];
            memcpy(M0, temp_block.data(), sizeof(M0));
            w0 = M0[0] ^ m0;
            w1 = M0[1] ^ m1;
            temp_block = ot_output[base_idx][1];
            memcpy(M1, temp_block.data(), sizeof(M1));
            corr_mesg[0] = M1[0] ^ m0 ^ w1;
            corr_mesg[1] = M1[1] ^ m1 ^ w0;
            correction_blocks[base_idx] = { corr_mesg[0], corr_mesg[1] };
            M1[0] = m0 ^ w1;
            M1[1] = m1 ^ w0;
            ot_output[base_idx][1] = { M1[0], M1[1] };
            src[0] = w0;
            src[1] = w1;
        }
        else
        {
            base_idx = (lvl_p + 1) * (Val / 2) + perm_idx;
            m0 = src[0];
            m1 = src[1];
            temp_block = ot_output[base_idx][0];
            memcpy(M0, temp_block.data(), sizeof(M0));
            w0 = M0[0] ^ m0;
            w1 = M0[1] ^ m1;
            temp_block = ot_output[base_idx][1];
            memcpy(M1, temp_block.data(), sizeof(M1));
            corr_mesg[0] = M1[0] ^ m0 ^ w1;
            corr_mesg[1] = M1[1] ^ m1 ^ w0;
            correction_blocks[base_idx] = { corr_mesg[0], corr_mesg[1] };
            M1[0] = m0 ^ w1;
            M1[1] = m1 ^ w0;
            ot_output[base_idx][1] = { M1[0], M1[1] };
            src[0] = w0;
            src[1] = w1;
        }
        return;
    }

    if (values == 3)
    {
        base_idx = lvl_p * (Val / 2) + perm_idx;
        m0 = src[0];
        m1 = src[1];
        temp_block = ot_output[base_idx][0];
        memcpy(M0, temp_block.data(), sizeof(M0));
        w0 = M0[0] ^ m0;
        w1 = M0[1] ^ m1;
        temp_block = ot_output[base_idx][1];
        memcpy(M1, temp_block.data(), sizeof(M1));
        corr_mesg[0] = M1[0] ^ m0 ^ w1;
        corr_mesg[1] = M1[1] ^ m1 ^ w0;
        correction_blocks[base_idx] = { corr_mesg[0], corr_mesg[1] };
        M1[0] = m0 ^ w1;
        M1[1] = m1 ^ w0;
        ot_output[base_idx][1] = { M1[0], M1[1] };
        src[0] = w0;
        src[1] = w1;

        base_idx = (lvl_p + 1) * (Val / 2) + perm_idx;
        m0 = src[1];
        m1 = src[2];
        temp_block = ot_output[base_idx][0];
        memcpy(M0, temp_block.data(), sizeof(M0));
        w0 = M0[0] ^ m0;
        w1 = M0[1] ^ m1;
        temp_block = ot_output[base_idx][1];
        memcpy(M1, temp_block.data(), sizeof(M1));
        corr_mesg[0] = M1[0] ^ m0 ^ w1;
        corr_mesg[1] = M1[1] ^ m1 ^ w0;
        correction_blocks[base_idx] = { corr_mesg[0], corr_mesg[1] };
        M1[0] = m0 ^ w1;
        M1[1] = m1 ^ w0;
        ot_output[base_idx][1] = { M1[0], M1[1] };
        src[1] = w0;
        src[2] = w1;

        base_idx = (lvl_p + 2) * (Val / 2) + perm_idx;
        m0 = src[0];
        m1 = src[1];
        temp_block = ot_output[base_idx][0];
        memcpy(M0, temp_block.data(), sizeof(M0));
        w0 = M0[0] ^ m0;
        w1 = M0[1] ^ m1;
        temp_block = ot_output[base_idx][1];
        memcpy(M1, temp_block.data(), sizeof(M1));
        corr_mesg[0] = M1[0] ^ m0 ^ w1;
        corr_mesg[1] = M1[1] ^ m1 ^ w0;
        correction_blocks[base_idx] = { corr_mesg[0], corr_mesg[1] };
        M1[0] = m0 ^ w1;
        M1[1] = m1 ^ w0;
        ot_output[base_idx][1] = { M1[0], M1[1] };
        src[0] = w0;
        src[1] = w1;
        return;
    }

    // partea superioara
    for (int i = 0; i < values - 1; i += 2)
    {
        base_idx = (lvl_p) * (Val / 2) + perm_idx + i / 2;
        m0 = src[i];
        m1 = src[i ^ 1];
        temp_block = ot_output[base_idx][0];
        memcpy(M0, temp_block.data(), sizeof(M0));
        w0 = M0[0] ^ m0;
        w1 = M0[1] ^ m1;
        temp_block = ot_output[base_idx][1];
        memcpy(M1, temp_block.data(), sizeof(M1));
        corr_mesg[0] = M1[0] ^ m0 ^ w1;
        corr_mesg[1] = M1[1] ^ m1 ^ w0;
        correction_blocks[base_idx] = { corr_mesg[0], corr_mesg[1] };
        M1[0] = m0 ^ w1;
        M1[1] = m1 ^ w0;
        ot_output[base_idx][1] = { M1[0], M1[1] };
        src[i] = w0;
        src[i ^ 1] = w1;

        bottom1.push_back(src[i]);
        top1.push_back(src[i ^ 1]);
    }

    if (values % 2 == 1)
    {
        top1.push_back(src[values - 1]);
    }

    cpus--;
    thread top_thrd, btm_thrd;
    if (cpus > 0)
    {
        top_thrd = thread(&OSN::prepare_correction, this, n - 1, Val, lvl_p + 1, perm_idx + values / 4, std::ref(top1), std::ref(ot_output), std::ref(correction_blocks));
    }
    else
    {
        prepare_correction(n - 1, Val, lvl_p + 1, perm_idx + values / 4, top1, ot_output, correction_blocks);
    }
    if (cpus > 0)
    {
        btm_thrd = thread(&OSN::prepare_correction, this, n - 1, Val, lvl_p + 1, perm_idx, std::ref(bottom1), std::ref(ot_output), std::ref(correction_blocks));
    }
    else
    {
        prepare_correction(n - 1, Val, lvl_p + 1, perm_idx, bottom1, ot_output, correction_blocks);
    }
    if (top_thrd.joinable())
        top_thrd.join();
    if (btm_thrd.joinable())
        btm_thrd.join();
    cpus++;

    // partea inferioara
    for (int i = 0; i < values - 1; i += 2)
    {
        base_idx = (lvl_p + levels - 1) * (Val / 2) + perm_idx + i / 2;
        m1 = top1[i / 2];
        m0 = bottom1[i / 2];
        temp_block = ot_output[base_idx][0];
        memcpy(M0, temp_block.data(), sizeof(M0));
        w0 = M0[0] ^ m0;
        w1 = M0[1] ^ m1;
        temp_block = ot_output[base_idx][1];
        memcpy(M1, temp_block.data(), sizeof(M1));
        corr_mesg[0] = M1[0] ^ m0 ^ w1;
        corr_mesg[1] = M1[1] ^ m1 ^ w0;
        correction_blocks[base_idx] = { corr_mesg[0], corr_mesg[1] };
        M1[0] = m0 ^ w1;
        M1[1] = m1 ^ w0;
        ot_output[base_idx][1] = { M1[0], M1[1] };
        src[i] = w0;
        src[i ^ 1] = w1;
    }

    int idx = int(ceil(values * 0.5));
    if (values % 2 == 1)
    {
        src[values - 1] = top1[idx - 1];
    }
}





