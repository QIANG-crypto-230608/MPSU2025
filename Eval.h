
#ifndef EVAL_H
#define EVAL_H

#include <string>
#include <cryptoTools/Common/TestCollection.h>
#include <macoro/when_all.h>
#include <macoro/sync_wait.h>
#include <macoro/task.h>

inline auto eval(macoro::task<>& t0, macoro::task<>& t1)
{
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(t0), std::move(t1)));
    std::get<0>(r).result();
    std::get<1>(r).result();
}


#endif
