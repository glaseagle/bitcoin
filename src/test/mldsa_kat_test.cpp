// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mldsa/mldsa.h>
#include <crypto/mldsa/mldsa_params.h>

#include <array>
#include <cstddef>
#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(mldsa_kat_tests)

BOOST_AUTO_TEST_CASE(size_constants)
{
    BOOST_CHECK_EQUAL(MLDSA_PUBLICKEYBYTES, 1952U);
    BOOST_CHECK_EQUAL(MLDSA_SECRETKEYBYTES, 4000U);
    BOOST_CHECK_EQUAL(MLDSA_SIGNBYTES, 3293U);

    BOOST_CHECK_EQUAL(MLDSA_PUBKEY_SIZE, MLDSA_PUBLICKEYBYTES);
    BOOST_CHECK_EQUAL(MLDSA_SECKEY_SIZE, MLDSA_SECRETKEYBYTES);
    BOOST_CHECK_EQUAL(MLDSA_SIG_SIZE, MLDSA_SIGNBYTES);
}

BOOST_AUTO_TEST_CASE(keygen_deterministic)
{
    std::array<uint8_t, 32> seed;
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i);
    }

    MLDSAPublicKey pk1, pk2;
    MLDSASecretKey sk1, sk2;

    BOOST_REQUIRE(MLDSA_KeyGen(pk1, sk1, seed.data()));
    BOOST_REQUIRE(MLDSA_KeyGen(pk2, sk2, seed.data()));

    BOOST_CHECK(pk1 == pk2);
    BOOST_CHECK(sk1 == sk2);
}

BOOST_AUTO_TEST_CASE(sign_verify_roundtrip)
{
    std::array<uint8_t, 32> seed;
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i);
    }
    const std::array<uint8_t, 32> msg{};
    std::array<uint8_t, 32> rnd;
    rnd.fill(1);

    MLDSAPublicKey pk;
    MLDSASecretKey sk;
    MLDSASignature sig;

    BOOST_REQUIRE(MLDSA_KeyGen(pk, sk, seed.data()));
    BOOST_REQUIRE(MLDSA_Sign(sig, msg.data(), msg.size(), sk, rnd.data()));
    BOOST_CHECK(MLDSA_Verify(sig, msg.data(), msg.size(), pk));
}

BOOST_AUTO_TEST_CASE(verify_wrong_key_fails)
{
    std::array<uint8_t, 32> seed1;
    std::array<uint8_t, 32> seed2;
    for (size_t i = 0; i < seed1.size(); ++i) {
        seed1[i] = static_cast<uint8_t>(i);
        seed2[i] = static_cast<uint8_t>(i + 1);
    }
    const std::array<uint8_t, 32> msg{};
    std::array<uint8_t, 32> rnd;
    rnd.fill(1);

    MLDSAPublicKey pk1, pk2;
    MLDSASecretKey sk1, sk2;
    MLDSASignature sig;

    BOOST_REQUIRE(MLDSA_KeyGen(pk1, sk1, seed1.data()));
    BOOST_REQUIRE(MLDSA_KeyGen(pk2, sk2, seed2.data()));
    BOOST_REQUIRE(MLDSA_Sign(sig, msg.data(), msg.size(), sk1, rnd.data()));
    BOOST_CHECK(!MLDSA_Verify(sig, msg.data(), msg.size(), pk2));
}

BOOST_AUTO_TEST_CASE(verify_wrong_message_fails)
{
    std::array<uint8_t, 32> seed;
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i);
    }
    std::array<uint8_t, 32> rnd;
    rnd.fill(1);
    const std::array<uint8_t, 32> msg{};
    std::array<uint8_t, 32> wrong_msg{};
    wrong_msg[0] = 1;

    MLDSAPublicKey pk;
    MLDSASecretKey sk;
    MLDSASignature sig;

    BOOST_REQUIRE(MLDSA_KeyGen(pk, sk, seed.data()));
    BOOST_REQUIRE(MLDSA_Sign(sig, msg.data(), msg.size(), sk, rnd.data()));
    BOOST_CHECK(!MLDSA_Verify(sig, wrong_msg.data(), wrong_msg.size(), pk));
}

BOOST_AUTO_TEST_CASE(verify_tampered_sig_fails)
{
    std::array<uint8_t, 32> seed;
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i);
    }
    const std::array<uint8_t, 32> msg{};
    std::array<uint8_t, 32> rnd;
    rnd.fill(1);

    MLDSAPublicKey pk;
    MLDSASecretKey sk;
    MLDSASignature sig;

    BOOST_REQUIRE(MLDSA_KeyGen(pk, sk, seed.data()));
    BOOST_REQUIRE(MLDSA_Sign(sig, msg.data(), msg.size(), sk, rnd.data()));

    MLDSASignature tampered_sig = sig;
    tampered_sig[0] ^= 1;
    BOOST_CHECK(!MLDSA_Verify(tampered_sig, msg.data(), msg.size(), pk));

    const MLDSASignature zero_sig{};
    BOOST_CHECK(!MLDSA_Verify(zero_sig, msg.data(), msg.size(), pk));
}

BOOST_AUTO_TEST_SUITE_END()
