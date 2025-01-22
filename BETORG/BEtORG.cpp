#include "BEtORG.h"
#include "libOTe/Base/SimplestOT.h"
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include "../Eval.h"
#include "batch_equality.h"

using namespace osuCrypto;
using namespace std;

//return recv, send;
std::pair<std::vector<oc::block>, std::vector<oc::block>> BETORG::run_betorg(
        std::vector<oc::block> send_input,
        std::vector<oc::block> recv_input,
        osuCrypto::cp::LocalAsyncSocket& ch0,
        osuCrypto::cp::LocalAsyncSocket& ch1,
        int* comm_beqt)
{
    int b = 5; int l = 61;
    int num_cmps_recv = recv_input.size();
    int num_cmps_send = send_input.size();
    uint8_t *res_shares_recv = new uint8_t[num_cmps_recv];
    uint8_t *res_shares_send = new uint8_t[num_cmps_send];

    uint64_t *alice_inputs = new uint64_t[recv_input.size()];
    uint64_t *bob_inputs = new uint64_t[send_input.size()];
    for(int i = 0; i < recv_input.size(); i++){
        auto ptr64 = reinterpret_cast<const uint64_t *> (&recv_input[i]);
        alice_inputs[i] = ptr64[0] & ((1ULL << 61) - 1);
    }

    for(int i = 0; i < send_input.size(); i++){
        auto ptr64 = reinterpret_cast<const uint64_t*> (&send_input[i]);
        bob_inputs[i] = ptr64[0] & ((1ULL << 61) - 1);
    }

    int alice_comm_cost = 0;
    int bob_comm_cost = 0;

    std::thread t_alice([&](){
        alice_comm_cost = beqt_thread(1,
                    b,
                    l,
                    num_cmps_recv,
                    9999,
                    alice_inputs,
                    res_shares_recv);
    });

    std::thread t_bob([&](){
        bob_comm_cost = beqt_thread(2,
                    b,
                    l,
                    num_cmps_send,
                    9999,
                    bob_inputs,
                    res_shares_send);
    });

    t_alice.join();
    t_bob.join();

    *comm_beqt = alice_comm_cost + bob_comm_cost;

    osuCrypto::BitVector recv_check_values(recv_input.size());
    for(int i = 0; i < recv_input.size(); i++){
        recv_check_values[i] = (res_shares_recv[i] == 1);
    }

    osuCrypto::BitVector send_check_values(send_input.size());
    for(int i = 0; i < send_input.size(); i++){
        send_check_values[i] = (res_shares_send[i] == 1);
    }

    std::vector<std::array<osuCrypto::block, 2>> send_sendMsg(send_input.size());
    std::vector<osuCrypto::block> send_recvMsg(send_input.size());
    osuCrypto::PRNG prng(osuCrypto::toBlock(4253465ULL, 23987045ULL));
    for(int i = 0; i < send_input.size(); i++){
        send_sendMsg[i][send_check_values[i]] = prng.get<osuCrypto::block>();
        send_sendMsg[i][send_check_values[i] ^ 1] = prng.get<osuCrypto::block>();
    }

    std::vector<osuCrypto::block> recv_recvMsg(recv_input.size());
    for(int i = 0; i < recv_input.size(); i++){
        recv_check_values[i] = recv_check_values[i] ^ 1;
    }

    base_ot(send_sendMsg, recv_recvMsg, recv_check_values, ch0, ch1);

    for(int i = 0; i < send_input.size(); i++){
        send_recvMsg[i] = send_sendMsg[i][send_check_values[i]];
    }

    return std::make_pair(recv_recvMsg, send_recvMsg);
}


void BETORG::base_ot(std::vector<std::array<osuCrypto::block, 2>>& sendMsg,
                  std::vector<osuCrypto::block>& recvMsg,
                  osuCrypto::BitVector& choices,
                  osuCrypto::cp::LocalAsyncSocket& ch0,
                  osuCrypto::cp::LocalAsyncSocket& ch1)
{
    osuCrypto::SimplestOT send_baseOTs;
    osuCrypto::PRNG prng0(osuCrypto::block(4253465, 3434565));
    auto p0 = send_baseOTs.send(sendMsg, prng0, ch0);

    osuCrypto::PRNG prng1(osuCrypto::block(42532335, 334565));
    osuCrypto::SimplestOT recv_baseOTs;
    auto p1 = recv_baseOTs.receive(choices, recvMsg, prng1, ch1);

    eval(p0,p1);
}


int beqt_thread(int party, int b, int l, int num_cmps, int port, uint64_t* input, uint8_t *res_shares)
{
    sci::NetIO* ioArr[2];
    if(party == 1){
        ioArr[0] = new sci::NetIO(nullptr, 10000);
        ioArr[1] = new sci::NetIO(nullptr, 10001);
    }else{
        ioArr[0] = new sci::NetIO("127.0.0.1", 10000);
        ioArr[1] = new sci::NetIO("127.0.0.1", 10001);
    }

    sci::OTPack<sci::NetIO> *otpackArr[2];
    otpackArr[0] = new OTPack<NetIO>(ioArr[0], party, b, l);
    otpackArr[1] = new OTPack<NetIO>(ioArr[1], 3 - party, b, l);
    BatchEquality<NetIO> *compare;

    compare = new BatchEquality<NetIO>(party, l, b, 3, num_cmps, ioArr[0], ioArr[1], otpackArr[0], otpackArr[1]);
    perform_batch_equality(input, compare, res_shares);


    int comm_cost = ioArr[0]->counter + ioArr[1]->counter;
    return comm_cost;
}