// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PQC_WALLET_H
#define BITCOIN_WALLET_PQC_WALLET_H

#include <crypto/mldsa/mldsa.h>
#include <script/script.h>
#include <serialize.h>

#include <array>
#include <cstdint>
#include <vector>

class CKey;

namespace wallet {

class CPQCKey
{
private:
    bool m_has_ecdsa{false};
    MLDSAPublicKey m_mldsa_pubkey{};
    MLDSASecretKey m_mldsa_seckey{};
    std::array<uint8_t, 33> m_ecdsa_pubkey{};
    std::array<uint8_t, 32> m_ecdsa_seckey{};

    CKey GetECDSAKey() const;

public:
    static CPQCKey Generate(bool hybrid);

    bool HasECDSA() const { return m_has_ecdsa; }
    const MLDSAPublicKey& GetMLDSAPubKey() const { return m_mldsa_pubkey; }
    const std::array<uint8_t, 33>& GetECDSAPubKey() const { return m_ecdsa_pubkey; }

    CScript GetP2PQHScript() const;
    CScript GetP2HPQScript() const;

    std::vector<std::vector<unsigned char>> SignP2PQH(std::span<const uint8_t, 32> sighash32) const;
    std::vector<std::vector<unsigned char>> SignP2HPQ(std::span<const uint8_t, 32> sighash32) const;

    SERIALIZE_METHODS(CPQCKey, obj)
    {
        READWRITE(obj.m_has_ecdsa, obj.m_mldsa_pubkey, obj.m_mldsa_seckey, obj.m_ecdsa_pubkey, obj.m_ecdsa_seckey);
    }
};

} // namespace wallet

#endif // BITCOIN_WALLET_PQC_WALLET_H
