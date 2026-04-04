// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/mldsa/mldsa.h>

#include <array>
#include <cstdint>

static constexpr size_t MLDSA_BENCH_ITERATIONS = 100;

static void Bench_MLDSA_KeyGen(benchmark::Bench& bench)
{
    std::array<uint8_t, 32> seed{};
    MLDSAPublicKey pubkey;
    MLDSASecretKey secret_key;

    bench.batch(1).unit("keygen").epochIterations(MLDSA_BENCH_ITERATIONS).run([&] {
        ++seed[0];
        const bool ok = MLDSA_KeyGen(pubkey, secret_key, seed.data());
        ankerl::nanobench::doNotOptimizeAway(ok);
        ankerl::nanobench::doNotOptimizeAway(pubkey);
        ankerl::nanobench::doNotOptimizeAway(secret_key);
    });
}

static void Bench_MLDSA_Sign(benchmark::Bench& bench)
{
    const std::array<uint8_t, 32> seed{1};
    const std::array<uint8_t, 32> message{2};
    MLDSAPublicKey pubkey;
    MLDSASecretKey secret_key;
    MLDSASignature signature;

    (void)MLDSA_KeyGen(pubkey, secret_key, seed.data());

    bench.batch(message.size()).unit("byte").run([&] {
        const bool ok = MLDSA_Sign(signature, message.data(), message.size(), secret_key);
        ankerl::nanobench::doNotOptimizeAway(ok);
        ankerl::nanobench::doNotOptimizeAway(signature);
    });
}

static void Bench_MLDSA_Verify(benchmark::Bench& bench)
{
    const std::array<uint8_t, 32> seed{3};
    const std::array<uint8_t, 32> message{4};
    MLDSAPublicKey pubkey;
    MLDSASecretKey secret_key;
    MLDSASignature signature;

    (void)MLDSA_KeyGen(pubkey, secret_key, seed.data());
    (void)MLDSA_Sign(signature, message.data(), message.size(), secret_key);

    bench.batch(message.size()).unit("byte").run([&] {
        const bool ok = MLDSA_Verify(signature, message.data(), message.size(), pubkey);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

static void Bench_MLDSA_Verify_Fail(benchmark::Bench& bench)
{
    const std::array<uint8_t, 32> seed{5};
    const std::array<uint8_t, 32> message{6};
    const std::array<uint8_t, 32> different_message{7};
    MLDSAPublicKey pubkey;
    MLDSASecretKey secret_key;
    MLDSASignature signature;

    (void)MLDSA_KeyGen(pubkey, secret_key, seed.data());
    (void)MLDSA_Sign(signature, message.data(), message.size(), secret_key);

    bench.batch(different_message.size()).unit("byte").run([&] {
        const bool ok = MLDSA_Verify(signature, different_message.data(), different_message.size(), pubkey);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

BENCHMARK(Bench_MLDSA_KeyGen);
BENCHMARK(Bench_MLDSA_Sign);
BENCHMARK(Bench_MLDSA_Verify);
BENCHMARK(Bench_MLDSA_Verify_Fail);
