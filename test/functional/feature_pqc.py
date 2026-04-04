#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQC SegWit v2 policy integration."""

from decimal import Decimal
import hashlib

from test_framework.address import address_to_scriptpubkey
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
)
from test_framework.script import (
    CScript,
    OP_2,
)
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

SEGWIT_VERSION_PQC = 2
PQC_TYPE_PURE = 0xc0
PQC_TYPE_RESERVED = 0xc1
PQC_TYPE_HYBRID = 0xc2
PQC_WITNESS_PROGRAM_SIZE = 21
PQC_HASH160_SIZE = 20
PQC_MLDSA_PUBKEY_BYTES = 1952
PQC_MLDSA_SIG_BYTES = 3293
PQC_ECDSA_SIG_MAX = 72
PQC_ECDSA_PUBKEY_BYTES = 33


class PQCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def skip_if_no_segwit(self):
        deployments = self.nodes[0].getdeploymentinfo()["deployments"]
        if not deployments.get("segwit", {}).get("active", False):
            raise SkipTest("SegWit is not active on this node")
        pqc = deployments.get("pqc")
        if pqc is None or not pqc.get("active", False):
            raise SkipTest("PQC SegWit v2 soft fork not yet activated")

    def tagged_hash20(self, tag):
        return hashlib.sha256(tag.encode("ascii")).digest()[:PQC_HASH160_SIZE]

    def pqc_program(self, type_byte, tag):
        program = bytes([type_byte]) + self.tagged_hash20(tag)
        assert_equal(len(program), PQC_WITNESS_PROGRAM_SIZE)
        return program

    def pqc_scriptpubkey(self, type_byte, tag):
        script_pub_key = CScript([OP_2, self.pqc_program(type_byte, tag)])
        assert_equal(len(script_pub_key), 23)
        return script_pub_key

    def compact_size_len(self, size):
        if size < 253:
            return 1
        if size < 0x10000:
            return 3
        if size < 0x100000000:
            return 5
        return 9

    def pop_wallet_utxo(self):
        utxos = self.wallet.listunspent()
        if not utxos:
            raise AssertionError("No spendable wallet UTXOs available")
        return utxos[0]

    def sats(self, amount):
        return int(Decimal(str(amount)) * COIN)

    def sign_wallet_spend(self, *, utxo, script_pub_key, fee_sat=1000):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), b"", SEQUENCE_FINAL)]
        tx.vout = [CTxOut(self.sats(utxo["amount"]) - fee_sat, script_pub_key)]
        signed = self.wallet.signrawtransactionwithwallet(tx.serialize().hex())
        assert signed["complete"]
        return signed["hex"]

    def make_p2pqh_spend(self, *, prev_txid, prev_value_sat, witness_stack, fee_sat=10_000):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(prev_txid, 16), 0), b"", SEQUENCE_FINAL)]
        tx.vout = [CTxOut(prev_value_sat - fee_sat, self.legacy_dest_script)]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx

    def assert_standard_output(self, *, type_byte, tag):
        tx_hex = self.sign_wallet_spend(
            utxo=self.pop_wallet_utxo(),
            script_pub_key=self.pqc_scriptpubkey(type_byte, tag),
        )
        decoded = self.nodes[0].decoderawtransaction(tx_hex)
        assert_equal(decoded["vout"][0]["scriptPubKey"]["type"], "witness_v2_pqc")
        res = self.nodes[0].testmempoolaccept([tx_hex])[0]
        assert_equal(res["allowed"], True)
        txid = self.nodes[0].sendrawtransaction(tx_hex)
        self.generatetoaddress(self.nodes[0], 1, self.mining_address)
        return txid

    def assert_nonstandard_output(self, *, type_byte, tag):
        tx_hex = self.sign_wallet_spend(
            utxo=self.pop_wallet_utxo(),
            script_pub_key=self.pqc_scriptpubkey(type_byte, tag),
        )
        decoded = self.nodes[0].decoderawtransaction(tx_hex)
        assert_equal(decoded["vout"][0]["scriptPubKey"]["type"], "witness_unknown")
        res = self.nodes[0].testmempoolaccept([tx_hex])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "scriptpubkey")
        assert_raises_rpc_error(-26, "scriptpubkey", self.nodes[0].sendrawtransaction, tx_hex)

    def test_output_recognition(self):
        self.log.info("Check that P2PQH and P2HPQ outputs are recognized as standard")
        self.assert_standard_output(type_byte=PQC_TYPE_PURE, tag="p2pqh-standard")
        self.assert_standard_output(type_byte=PQC_TYPE_HYBRID, tag="p2hpq-standard")

        self.log.info("Check that unknown SegWit v2 PQC type bytes are non-standard")
        self.assert_nonstandard_output(type_byte=PQC_TYPE_RESERVED, tag="pqc-reserved")
        self.assert_nonstandard_output(type_byte=0xaa, tag="pqc-unknown")

    def test_p2pqh_witness_policy(self):
        self.log.info("Check P2PQH witness policy and vsize calculation")
        fund_tx_hex = self.sign_wallet_spend(
            utxo=self.pop_wallet_utxo(),
            script_pub_key=self.pqc_scriptpubkey(PQC_TYPE_PURE, "p2pqh-funding"),
            fee_sat=2000,
        )
        fund_txid = self.nodes[0].sendrawtransaction(fund_tx_hex)
        self.generatetoaddress(self.nodes[0], 1, self.mining_address)
        fund_tx = self.nodes[0].getrawtransaction(fund_txid, True)
        prev_value_sat = self.sats(fund_tx["vout"][0]["value"])

        correct_witness = [
            b"\x11" * PQC_MLDSA_SIG_BYTES + b"\x00",
            b"\x22" * PQC_MLDSA_PUBKEY_BYTES,
        ]
        sized_tx = self.make_p2pqh_spend(
            prev_txid=fund_txid,
            prev_value_sat=prev_value_sat,
            witness_stack=correct_witness,
        )
        witness_size = (
            2
            + 1
            + self.compact_size_len(PQC_MLDSA_SIG_BYTES + 1) + PQC_MLDSA_SIG_BYTES + 1
            + self.compact_size_len(PQC_MLDSA_PUBKEY_BYTES) + PQC_MLDSA_PUBKEY_BYTES
        )
        base_size = 4 + 1 + 36 + 1 + 4 + 1 + 8 + self.compact_size_len(len(self.legacy_dest_script)) + len(self.legacy_dest_script) + 4
        expected_vsize = (base_size * 4 + witness_size + 3) // 4
        assert_equal(sized_tx.get_vsize(), expected_vsize)
        assert_equal(self.nodes[0].decoderawtransaction(sized_tx.serialize().hex())["vsize"], expected_vsize)

        malformed_tx = self.make_p2pqh_spend(
            prev_txid=fund_txid,
            prev_value_sat=prev_value_sat,
            witness_stack=[
                b"\x33" * PQC_MLDSA_SIG_BYTES,
                b"\x44" * PQC_MLDSA_PUBKEY_BYTES,
            ],
        )
        malformed_hex = malformed_tx.serialize().hex()
        res = self.nodes[0].testmempoolaccept([malformed_hex])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "bad-witness-nonstandard")
        assert_raises_rpc_error(-26, "bad-witness-nonstandard", self.nodes[0].sendrawtransaction, malformed_hex)

    def run_test(self):
        self.skip_if_no_segwit()

        self.wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.mining_address = self.wallet.getnewaddress()
        self.legacy_dest_script = address_to_scriptpubkey(self.wallet.getnewaddress(address_type="legacy"))

        self.generatetoaddress(self.nodes[0], 110, self.mining_address)

        self.test_output_recognition()
        self.test_p2pqh_witness_policy()


if __name__ == '__main__':
    PQCTest(__file__).main()
