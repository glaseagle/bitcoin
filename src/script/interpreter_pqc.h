// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_PQC_H
#define BITCOIN_SCRIPT_INTERPRETER_PQC_H

#include <primitives/transaction.h>
#include <script/script_error.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

// PQC: Minimal transaction context required for BIP-PQC sighash computation.
struct PQCTxContext {
    uint32_t nVersion;
    uint32_t nLocktime;
    uint32_t nIn;
    int64_t amount;
    uint32_t nSequence;
    std::array<uint8_t, 32> prevout_hash;
    uint32_t prevout_n;
    std::vector<uint8_t> outputs_serialized;
    std::array<uint8_t, 21> witness_program;
};

// PQC: ScriptError extension values kept local to the PQC interpreter bridge.
static constexpr ScriptError SCRIPT_ERR_PQC_BAD_PROGRAM_SIZE =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 0);
static constexpr ScriptError SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 1);
static constexpr ScriptError SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 2);
static constexpr ScriptError SCRIPT_ERR_PQC_PUBKEY_MISMATCH =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 3);
static constexpr ScriptError SCRIPT_ERR_PQC_BAD_SIG_SIZE =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 4);
static constexpr ScriptError SCRIPT_ERR_PQC_UNKNOWN_SIGHASH =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 5);
static constexpr ScriptError SCRIPT_ERR_PQC_SIGHASH_MISMATCH =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 6);
static constexpr ScriptError SCRIPT_ERR_PQC_SIG_INVALID =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 7);
static constexpr ScriptError SCRIPT_ERR_PQC_UNKNOWN_TYPE =
    static_cast<ScriptError>(SCRIPT_ERR_ERROR_COUNT + 8);

bool VerifyPQCWitnessProgram(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t> program,
    const PQCTxContext& ctx,
    ScriptError* serror);

bool VerifyP2PQH(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t, 21> program,
    const PQCTxContext& ctx,
    ScriptError* serror);

bool VerifyP2HPQ(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t, 21> program,
    const PQCTxContext& ctx,
    ScriptError* serror);

#endif // BITCOIN_SCRIPT_INTERPRETER_PQC_H
