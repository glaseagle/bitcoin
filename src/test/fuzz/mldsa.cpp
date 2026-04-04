// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/mldsa/mldsa.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

static_assert(MLDSA_PUBKEY_SIZE == 1952);
static_assert(MLDSA_SECKEY_SIZE == 4032);
static_assert(MLDSA_SIG_SIZE == 3293);

FUZZ_TARGET(mldsa_verify)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const std::vector<uint8_t> pubkey_bytes{
        fuzzed_data_provider.ConsumeBytes<uint8_t>(MLDSA_PUBKEY_SIZE)
    };
    const std::vector<uint8_t> message{
        ConsumeRandomLengthByteVector(fuzzed_data_provider)
    };
    const std::vector<uint8_t> signature_bytes{
        fuzzed_data_provider.ConsumeBytes<uint8_t>(MLDSA_SIG_SIZE)
    };

    if (pubkey_bytes.size() != MLDSA_PUBKEY_SIZE || signature_bytes.size() != MLDSA_SIG_SIZE) return;

    MLDSAPublicKey pubkey;
    std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());

    MLDSASignature signature;
    std::copy(signature_bytes.begin(), signature_bytes.end(), signature.begin());

    (void)MLDSA_Verify(signature, message.data(), message.size(), pubkey);
}

FUZZ_TARGET(mldsa_sign)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const std::vector<uint8_t> secret_key_bytes{
        fuzzed_data_provider.ConsumeBytes<uint8_t>(MLDSA_SECKEY_SIZE)
    };
    const std::vector<uint8_t> message{
        ConsumeRandomLengthByteVector(fuzzed_data_provider)
    };

    if (secret_key_bytes.size() != MLDSA_SECKEY_SIZE) return;

    MLDSASecretKey secret_key;
    std::copy(secret_key_bytes.begin(), secret_key_bytes.end(), secret_key.begin());

    MLDSASignature signature;
    (void)MLDSA_Sign(signature, message.data(), message.size(), secret_key);
}
