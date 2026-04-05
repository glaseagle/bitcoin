// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pqc_wallet.h>

#include <crypto/mldsa/mldsa.h>
#include <hash.h>
#include <key.h>
#include <random.h>
#include <script/script_pqc.h>

#include <array>
#include <span>
#include <stdexcept>
#include <vector>

namespace wallet {
namespace {

std::array<uint8_t, 20> Hash160Span(std::span<const uint8_t> data)
{
    std::array<uint8_t, 20> out{};
    std::span<unsigned char> out_span(reinterpret_cast<unsigned char*>(out.data()), out.size());
    CHash160().Write(MakeUCharSpan(data)).Finalize(out_span);
    return out;
}

std::array<uint8_t, 20> BuildCommitmentHash(const CPQCKey& key, uint8_t type)
{
    std::vector<uint8_t> commitment;
    commitment.reserve(1 + (type == PQC_TYPE_HYBRID ? PQC_ECDSA_PUBKEY_BYTES : 0) + PQC_MLDSA_PUBKEY_BYTES);
    commitment.push_back(type);
    if (type == PQC_TYPE_HYBRID) {
        const auto& ecdsa_pubkey = key.GetECDSAPubKey();
        commitment.insert(commitment.end(), ecdsa_pubkey.begin(), ecdsa_pubkey.end());
    }
    const auto& mldsa_pubkey = key.GetMLDSAPubKey();
    commitment.insert(commitment.end(), mldsa_pubkey.begin(), mldsa_pubkey.end());
    return Hash160Span(commitment);
}

} // namespace

CKey CPQCKey::GetECDSAKey() const
{
    if (!m_has_ecdsa) {
        throw std::runtime_error("CPQCKey does not have a hybrid ECDSA key");
    }
    CKey key;
    key.Set(m_ecdsa_seckey.begin(), m_ecdsa_seckey.end(), true);
    return key;
}

CPQCKey CPQCKey::Generate(bool hybrid)
{
    CPQCKey out;

    std::array<uint8_t, 32> seed{};
    GetStrongRandBytes(seed);
    if (!MLDSA_KeyGen(out.m_mldsa_pubkey, out.m_mldsa_seckey, seed.data())) {
        throw std::runtime_error("MLDSA_KeyGen failed");
    }

    if (hybrid) {
        CKey ecdsa_key;
        ecdsa_key.MakeNewKey(/*fCompressed=*/true);
        const CPubKey pubkey = ecdsa_key.GetPubKey();
        std::copy(pubkey.begin(), pubkey.end(), out.m_ecdsa_pubkey.begin());
        std::transform(ecdsa_key.begin(), ecdsa_key.end(), out.m_ecdsa_seckey.begin(), [](std::byte b) {
            return static_cast<uint8_t>(b);
        });
        out.m_has_ecdsa = true;
    }

    return out;
}

CScript CPQCKey::GetP2PQHScript() const
{
    const auto hash = BuildCommitmentHash(*this, PQC_TYPE_PURE);
    const auto spk = BuildPQCScriptPubKey(PQC_TYPE_PURE, hash);
    return CScript(spk.begin(), spk.end());
}

CScript CPQCKey::GetP2HPQScript() const
{
    if (!m_has_ecdsa) {
        throw std::runtime_error("P2HPQ requires hybrid key material");
    }
    const auto hash = BuildCommitmentHash(*this, PQC_TYPE_HYBRID);
    const auto spk = BuildPQCScriptPubKey(PQC_TYPE_HYBRID, hash);
    return CScript(spk.begin(), spk.end());
}

std::vector<std::vector<unsigned char>> CPQCKey::SignP2PQH(std::span<const uint8_t, 32> sighash32) const
{
    MLDSASignature mldsa_sig{};
    if (!MLDSA_Sign(mldsa_sig, sighash32.data(), sighash32.size(), m_mldsa_seckey)) {
        throw std::runtime_error("MLDSA_Sign failed");
    }

    std::vector<unsigned char> sig(mldsa_sig.begin(), mldsa_sig.end());
    sig.push_back(0x00);
    return {
        std::move(sig),
        std::vector<unsigned char>(m_mldsa_pubkey.begin(), m_mldsa_pubkey.end()),
    };
}

std::vector<std::vector<unsigned char>> CPQCKey::SignP2HPQ(std::span<const uint8_t, 32> sighash32) const
{
    CKey ecdsa_key = GetECDSAKey();

    uint256 hash;
    std::copy(sighash32.begin(), sighash32.end(), hash.begin());

    std::vector<unsigned char> ecdsa_sig;
    if (!ecdsa_key.Sign(hash, ecdsa_sig)) {
        throw std::runtime_error("ECDSA signing failed");
    }
    ecdsa_sig.push_back(0x00);

    const auto p2pqh = SignP2PQH(sighash32);
    return {
        std::move(ecdsa_sig),
        std::vector<unsigned char>(m_ecdsa_pubkey.begin(), m_ecdsa_pubkey.end()),
        p2pqh[0],
        p2pqh[1],
    };
}

} // namespace wallet
