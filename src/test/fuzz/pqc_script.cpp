// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter_pqc.h>
#include <script/script_pqc.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

FUZZ_TARGET(pqc_script)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const size_t witness_items{
        fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 8)
    };
    std::vector<std::vector<uint8_t>> witness;
    witness.reserve(witness_items);
    for (size_t i = 0; i < witness_items; ++i) {
        witness.push_back(ConsumeRandomLengthByteVector(fuzzed_data_provider));
    }

    const std::vector<uint8_t> program{
        ConsumeRandomLengthByteVector(fuzzed_data_provider, PQC_WITNESS_PROGRAM_SIZE)
    };

    PQCTxContext ctx{};
    if (program.size() == ctx.witness_program.size()) {
        std::copy(program.begin(), program.end(), ctx.witness_program.begin());
    }

    ScriptError script_error;
    (void)VerifyPQCWitnessProgram(witness, program, ctx, &script_error);
}
