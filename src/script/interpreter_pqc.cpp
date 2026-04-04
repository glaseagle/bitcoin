// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter_pqc.h>

#include <crypto/mldsa/mldsa.h>
#include <hash.h>
#include <script/script_pqc.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>

// PQC: TODO: replace this extern bridge with direct secp256k1-backed verification wiring.
extern bool ECDSAVerify(
    std::span<const uint8_t> sig,
    std::span<const uint8_t> hash,
    std::span<const uint8_t> pubkey);

namespace {

static void WriteLE32(std::vector<uint8_t>& out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}

static void WriteLE64(std::vector<uint8_t>& out, uint64_t value)
{
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 32));
    out.push_back(static_cast<uint8_t>(value >> 40));
    out.push_back(static_cast<uint8_t>(value >> 48));
    out.push_back(static_cast<uint8_t>(value >> 56));
}

// PQC: Bitcoin Core Hash160 wrapper used in place of the standalone helper.
static std::array<uint8_t, 20> Hash160Impl(std::span<const uint8_t> data)
{
    std::array<uint8_t, 20> out{};
    CHash160().Write(data).Finalize(out);
    return out;
}

static std::array<uint8_t, 32> ToByteArray(const uint256& hash)
{
    std::array<uint8_t, 32> out{};
    std::copy(hash.begin(), hash.end(), out.begin());
    return out;
}

static bool CheckItemSize(
    std::span<const uint8_t> item,
    size_t expected,
    ScriptError* serror,
    ScriptError code)
{
    if (item.size() != expected) {
        if (serror) *serror = code;
        return false;
    }
    return true;
}

static bool ParseMLDSASig(
    std::span<const uint8_t> raw,
    std::span<const uint8_t, PQC_MLDSA_SIG_BYTES>& sig_out,
    uint8_t& sighash_type_out,
    ScriptError* serror)
{
    constexpr size_t WIRE_SIZE = PQC_MLDSA_SIG_BYTES + 1;
    if (raw.size() != WIRE_SIZE) {
        if (serror) *serror = SCRIPT_ERR_PQC_BAD_SIG_SIZE;
        return false;
    }
    sig_out = std::span<const uint8_t, PQC_MLDSA_SIG_BYTES>{raw.data(), PQC_MLDSA_SIG_BYTES};
    sighash_type_out = raw[PQC_MLDSA_SIG_BYTES];
    if (sighash_type_out != 0x00) {
        if (serror) *serror = SCRIPT_ERR_PQC_UNKNOWN_SIGHASH;
        return false;
    }
    return true;
}

static bool ParseECDSASig(
    std::span<const uint8_t> raw,
    std::span<const uint8_t>& der_sig_out,
    uint8_t& sighash_type_out,
    ScriptError* serror)
{
    if (raw.size() < PQC_ECDSA_SIG_MIN + 1 || raw.size() > PQC_ECDSA_SIG_MAX + 1) {
        if (serror) *serror = SCRIPT_ERR_PQC_BAD_SIG_SIZE;
        return false;
    }
    sighash_type_out = raw.back();
    if (sighash_type_out != 0x00) {
        if (serror) *serror = SCRIPT_ERR_PQC_UNKNOWN_SIGHASH;
        return false;
    }
    der_sig_out = raw.subspan(0, raw.size() - 1);
    return true;
}

} // namespace

std::array<uint8_t, 32> ComputePQCSigHash(
    const PQCTxContext& ctx,
    uint8_t sighash_type)
{
    std::vector<uint8_t> prevouts;
    prevouts.reserve(36);
    prevouts.insert(prevouts.end(), ctx.prevout_hash.begin(), ctx.prevout_hash.end());
    WriteLE32(prevouts, ctx.prevout_n);
    const auto hash_prevouts = ToByteArray(Hash(prevouts));

    std::vector<uint8_t> sequences;
    sequences.reserve(4);
    WriteLE32(sequences, ctx.nSequence);
    const auto hash_sequences = ToByteArray(Hash(sequences));

    const auto hash_outputs = ToByteArray(Hash(ctx.outputs_serialized));

    std::vector<uint8_t> preimage;
    preimage.reserve(4 + 32 + 32 + 36 + 8 + 4 + 32 + 4 + 1 + ctx.witness_program.size());
    WriteLE32(preimage, ctx.nVersion);
    preimage.insert(preimage.end(), hash_prevouts.begin(), hash_prevouts.end());
    preimage.insert(preimage.end(), hash_sequences.begin(), hash_sequences.end());
    preimage.insert(preimage.end(), ctx.prevout_hash.begin(), ctx.prevout_hash.end());
    WriteLE32(preimage, ctx.prevout_n);
    WriteLE64(preimage, static_cast<uint64_t>(ctx.amount));
    WriteLE32(preimage, ctx.nSequence);
    preimage.insert(preimage.end(), hash_outputs.begin(), hash_outputs.end());
    WriteLE32(preimage, ctx.nLocktime);
    preimage.push_back(sighash_type);
    preimage.insert(preimage.end(), ctx.witness_program.begin(), ctx.witness_program.end());

    return ToByteArray(Hash(preimage));
}

bool VerifyP2PQH(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t, PQC_WITNESS_PROGRAM_SIZE> program,
    const PQCTxContext& ctx,
    ScriptError* serror)
{
    if (witness.size() != PQC_WIT_P2PQH_ITEMS) {
        if (serror) *serror = SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS;
        return false;
    }

    std::span<const uint8_t> raw_sig{witness[PQC_WIT_MLDSA_SIG]};
    std::span<const uint8_t> raw_pk{witness[PQC_WIT_MLDSA_PK]};

    if (!CheckItemSize(raw_pk, PQC_MLDSA_PUBKEY_BYTES, serror, SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE)) {
        return false;
    }

    const auto h160 = Hash160Impl(raw_pk);
    const auto prog_hash = program.subspan<PQC_HASH_OFFSET, PQC_HASH160_SIZE>();
    if (std::memcmp(h160.data(), prog_hash.data(), PQC_HASH160_SIZE) != 0) {
        if (serror) *serror = SCRIPT_ERR_PQC_PUBKEY_MISMATCH;
        return false;
    }

    std::span<const uint8_t, PQC_MLDSA_SIG_BYTES> mldsa_sig{raw_sig.data(), PQC_MLDSA_SIG_BYTES};
    uint8_t sighash_type{};
    if (!ParseMLDSASig(raw_sig, mldsa_sig, sighash_type, serror)) {
        return false;
    }

    const auto sighash = ComputePQCSigHash(ctx, sighash_type);

    MLDSAPublicKey pk_arr;
    std::copy(raw_pk.begin(), raw_pk.end(), pk_arr.begin());

    MLDSASignature sig_arr;
    std::copy(mldsa_sig.begin(), mldsa_sig.end(), sig_arr.begin());

    if (!MLDSA_Verify(sig_arr, sighash.data(), sighash.size(), pk_arr)) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIG_INVALID;
        return false;
    }

    if (serror) *serror = SCRIPT_ERR_OK;
    return true;
}

bool VerifyP2HPQ(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t, PQC_WITNESS_PROGRAM_SIZE> program,
    const PQCTxContext& ctx,
    ScriptError* serror)
{
    if (witness.size() != PQC_WIT_P2HPQ_ITEMS) {
        if (serror) *serror = SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS;
        return false;
    }

    std::span<const uint8_t> raw_ecdsa_sig{witness[HPQ_WIT_ECDSA_SIG]};
    std::span<const uint8_t> raw_ecdsa_pk{witness[HPQ_WIT_ECDSA_PK]};
    std::span<const uint8_t> raw_mldsa_sig{witness[HPQ_WIT_MLDSA_SIG]};
    std::span<const uint8_t> raw_mldsa_pk{witness[HPQ_WIT_MLDSA_PK]};

    if (!CheckItemSize(raw_ecdsa_pk, PQC_ECDSA_PUBKEY_BYTES, serror, SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE)) {
        return false;
    }
    if (!CheckItemSize(raw_mldsa_pk, PQC_MLDSA_PUBKEY_BYTES, serror, SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE)) {
        return false;
    }

    {
        std::vector<uint8_t> combined;
        combined.reserve(raw_ecdsa_pk.size() + raw_mldsa_pk.size());
        combined.insert(combined.end(), raw_ecdsa_pk.begin(), raw_ecdsa_pk.end());
        combined.insert(combined.end(), raw_mldsa_pk.begin(), raw_mldsa_pk.end());
        const auto h160 = Hash160Impl(combined);
        const auto prog_hash = program.subspan<PQC_HASH_OFFSET, PQC_HASH160_SIZE>();
        if (std::memcmp(h160.data(), prog_hash.data(), PQC_HASH160_SIZE) != 0) {
            if (serror) *serror = SCRIPT_ERR_PQC_PUBKEY_MISMATCH;
            return false;
        }
    }

    std::span<const uint8_t> ecdsa_der;
    uint8_t ecdsa_sighash_type{};
    if (!ParseECDSASig(raw_ecdsa_sig, ecdsa_der, ecdsa_sighash_type, serror)) {
        return false;
    }

    std::span<const uint8_t, PQC_MLDSA_SIG_BYTES> mldsa_sig{raw_mldsa_sig.data(), PQC_MLDSA_SIG_BYTES};
    uint8_t mldsa_sighash_type{};
    if (!ParseMLDSASig(raw_mldsa_sig, mldsa_sig, mldsa_sighash_type, serror)) {
        return false;
    }

    if (ecdsa_sighash_type != mldsa_sighash_type) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIGHASH_MISMATCH;
        return false;
    }

    const auto sighash = ComputePQCSigHash(ctx, ecdsa_sighash_type);

    if (!ECDSAVerify(ecdsa_der, sighash, raw_ecdsa_pk)) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIG_INVALID;
        return false;
    }

    MLDSAPublicKey pk_arr;
    std::copy(raw_mldsa_pk.begin(), raw_mldsa_pk.end(), pk_arr.begin());

    MLDSASignature sig_arr;
    std::copy(mldsa_sig.begin(), mldsa_sig.end(), sig_arr.begin());

    if (!MLDSA_Verify(sig_arr, sighash.data(), sighash.size(), pk_arr)) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIG_INVALID;
        return false;
    }

    if (serror) *serror = SCRIPT_ERR_OK;
    return true;
}

bool VerifyPQCWitnessProgram(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t> program_raw,
    const PQCTxContext& ctx,
    ScriptError* serror)
{
    if (program_raw.size() != PQC_WITNESS_PROGRAM_SIZE) {
        if (serror) *serror = SCRIPT_ERR_PQC_BAD_PROGRAM_SIZE;
        return false;
    }

    std::span<const uint8_t, PQC_WITNESS_PROGRAM_SIZE> program{
        program_raw.data(), PQC_WITNESS_PROGRAM_SIZE
    };

    const uint8_t type_byte = program[PQC_TYPE_OFFSET];

    switch (type_byte) {
    case PQC_TYPE_PURE:
        return VerifyP2PQH(witness, program, ctx, serror);
    case PQC_TYPE_HYBRID:
        return VerifyP2HPQ(witness, program, ctx, serror);
    default:
        if (serror) *serror = SCRIPT_ERR_PQC_UNKNOWN_TYPE;
        return false;
    }
}
