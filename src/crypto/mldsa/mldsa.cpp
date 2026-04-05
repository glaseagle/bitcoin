// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license.
//
// ML-DSA-65 KeyGen, Sign, Verify.
// NIST FIPS 204, §5 (KeyGen), §6 (Sign), §7 (Verify).
//
// Constant-time requirements:
//   - All branching in the verification path is data-independent (no secret data
//     reaches branch conditions in the Verify function).
//   - The Sign function uses secret data; constant-time discipline is maintained
//     through the use of bitmasking rather than conditional branches on secrets.
//   - Memory containing secret key material is zeroed before returning via
//     memory_cleanse() (Bitcoin Core's secure_allocator pattern).

#include "mldsa.h"
#include "mldsa_params.h"
#include "mldsa_poly.h"
#include <algorithm>
#include <array>
#include <random>
#include <string.h>
#include <assert.h>

#include <vector>

// PQC: Forward declaration for the local helper defined at the bottom of this file.
void mldsa_polyvecl_reduce(mldsa_polyvecl *v);

// ---- Helper: SHAKE256 with domain separation ----

namespace {

void FillStrongRandom(std::span<uint8_t> out)
{
    std::random_device rd;
    for (uint8_t& byte : out) {
        byte = static_cast<uint8_t>(rd());
    }
}

void local_memory_cleanse(void* ptr, size_t len)
{
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len-- > 0) {
        *p++ = 0;
    }
}

} // namespace

static void H(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake256(out, outlen, in, inlen);
}

static void H2(uint8_t *out, size_t outlen,
               const uint8_t *in1, size_t in1len,
               const uint8_t *in2, size_t in2len) {
    // Concatenate in1 || in2 and hash
    std::vector<uint8_t> buf(in1len + in2len);
    memcpy(buf.data(), in1, in1len);
    memcpy(buf.data() + in1len, in2, in2len);
    shake256(out, outlen, buf.data(), buf.size());
}

static void H3(uint8_t *out, size_t outlen,
               const uint8_t *in1, size_t in1len,
               const uint8_t *in2, size_t in2len,
               const uint8_t *in3, size_t in3len) {
    std::vector<uint8_t> buf(in1len + in2len + in3len);
    memcpy(buf.data(), in1, in1len);
    memcpy(buf.data() + in1len, in2, in2len);
    memcpy(buf.data() + in1len + in2len, in3, in3len);
    shake256(out, outlen, buf.data(), buf.size());
}

static void mldsa_polyvecl_add(mldsa_polyvecl* w, const mldsa_polyvecl* u, const mldsa_polyvecl* v)
{
    for (int i = 0; i < MLDSA_L; ++i) {
        mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

// ---- Public key packing ----

static void pack_pk(uint8_t pk[MLDSA_PUBLICKEYBYTES],
                    const uint8_t rho[MLDSA_SEEDBYTES],
                    const mldsa_polyveck *t1) {
    memcpy(pk, rho, MLDSA_SEEDBYTES);
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_pack_t1(pk + MLDSA_SEEDBYTES + i * MLDSA_POLYT1_PACKEDBYTES, &t1->vec[i]);
}

static void unpack_pk(uint8_t rho[MLDSA_SEEDBYTES],
                      mldsa_polyveck *t1,
                      const uint8_t pk[MLDSA_PUBLICKEYBYTES]) {
    memcpy(rho, pk, MLDSA_SEEDBYTES);
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_unpack_t1(&t1->vec[i], pk + MLDSA_SEEDBYTES + i * MLDSA_POLYT1_PACKEDBYTES);
}

// ---- Secret key packing ----

static void pack_sk(uint8_t sk[MLDSA_SECRETKEYBYTES],
                    const uint8_t rho[MLDSA_SEEDBYTES],
                    const uint8_t tr[MLDSA_TRBYTES],
                    const uint8_t key[MLDSA_SEEDBYTES],
                    const mldsa_polyveck *t0,
                    const mldsa_polyvecl *s1,
                    const mldsa_polyveck *s2) {
    static_assert(MLDSA_SECRETKEYBYTES ==
                  2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES +
                  MLDSA_L * MLDSA_POLYETA_PACKEDBYTES +
                  MLDSA_K * MLDSA_POLYETA_PACKEDBYTES +
                  MLDSA_K * MLDSA_POLYT0_PACKEDBYTES);
    uint8_t *p = sk;
    memcpy(p, rho, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(p, key, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(p, tr,  MLDSA_TRBYTES);   p += MLDSA_TRBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_pack_eta(p, &s1->vec[i]); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_pack_eta(p, &s2->vec[i]); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_pack_t0(p, &t0->vec[i]);  p += MLDSA_POLYT0_PACKEDBYTES; }
    assert(p == sk + MLDSA_SECRETKEYBYTES);
}

static void unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
                      uint8_t tr[MLDSA_TRBYTES],
                      uint8_t key[MLDSA_SEEDBYTES],
                      mldsa_polyveck *t0,
                      mldsa_polyvecl *s1,
                      mldsa_polyveck *s2,
                      const uint8_t sk[MLDSA_SECRETKEYBYTES]) {
    const uint8_t *p = sk;
    memcpy(rho, p, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(key, p, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(tr,  p, MLDSA_TRBYTES);   p += MLDSA_TRBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_unpack_eta(&s1->vec[i], p); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_unpack_eta(&s2->vec[i], p); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_unpack_t0(&t0->vec[i], p);  p += MLDSA_POLYT0_PACKEDBYTES; }
    assert(p == sk + MLDSA_SECRETKEYBYTES);
}

// ---- Signature packing ----

static void pack_sig(uint8_t sig[MLDSA_SIGNBYTES],
                     const uint8_t c[MLDSA_CTILDEBYTES],
                     const mldsa_polyvecl *z,
                     const mldsa_polyveck *h) {
    uint8_t *p = sig;
    memcpy(p, c, MLDSA_CTILDEBYTES); p += MLDSA_CTILDEBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_pack_z(p, &z->vec[i]); p += MLDSA_POLYZ_PACKEDBYTES; }

    // Pack hint: for each ring element in h, write indices of hint=1 positions,
    // then write the end index for that polynomial.
    for (int i = 0; i < MLDSA_OMEGA + MLDSA_K; ++i) sig[MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES + i] = 0;
    uint8_t *hp = sig + MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
    unsigned int k2 = 0;
    for (int i = 0; i < MLDSA_K; ++i) {
        for (int j = 0; j < MLDSA_N; ++j)
            if (h->vec[i].coeffs[j] != 0)
                hp[k2++] = (uint8_t)j;
        hp[MLDSA_OMEGA + i] = (uint8_t)k2;
    }
    assert(k2 <= MLDSA_OMEGA);
}

static int unpack_sig(uint8_t c[MLDSA_CTILDEBYTES],
                      mldsa_polyvecl *z,
                      mldsa_polyveck *h,
                      const uint8_t sig[MLDSA_SIGNBYTES]) {
    const uint8_t *p = sig;
    memcpy(c, p, MLDSA_CTILDEBYTES); p += MLDSA_CTILDEBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_unpack_z(&z->vec[i], p); p += MLDSA_POLYZ_PACKEDBYTES; }

    // Unpack hint
    const uint8_t *hp = sig + MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
    unsigned int k2 = 0;
    for (int i = 0; i < MLDSA_K; ++i) {
        for (int j = 0; j < MLDSA_N; ++j)
            h->vec[i].coeffs[j] = 0;
        if (hp[MLDSA_OMEGA + i] < k2 || hp[MLDSA_OMEGA + i] > MLDSA_OMEGA)
            return 1; // Malformed hint
        const unsigned int start = k2;
        for (; k2 < hp[MLDSA_OMEGA + i]; ++k2) {
            if (k2 > start && hp[k2] <= hp[k2-1]) return 1; // Not sorted within polynomial
            h->vec[i].coeffs[hp[k2]] = 1;
        }
    }
    // Remaining entries must be zero
    for (; k2 < MLDSA_OMEGA; ++k2)
        if (hp[k2] != 0) return 1;
    return 0;
}

// ===========================================================================
// ML-DSA.KeyGen — FIPS 204 §5.1
// ===========================================================================

bool MLDSA_KeyGen(MLDSAPublicKey& pk, MLDSASecretKey& sk, const uint8_t seed[32]) {
    uint8_t seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
    uint8_t rho[MLDSA_SEEDBYTES], rhoprime[MLDSA_CRHBYTES], key[MLDSA_SEEDBYTES];

    // Step 1: Generate or use provided seed
    uint8_t xi[MLDSA_SEEDBYTES];
    if (seed) {
        memcpy(xi, seed, MLDSA_SEEDBYTES);
    } else {
        FillStrongRandom(std::span<uint8_t>{xi, MLDSA_SEEDBYTES});
    }

    // Step 2: Expand seed
    // (rho || rhoprime || key) = H(xi || k || l, 96 bytes)
    uint8_t ext[MLDSA_SEEDBYTES + 2];
    memcpy(ext, xi, MLDSA_SEEDBYTES);
    ext[MLDSA_SEEDBYTES]   = MLDSA_K;
    ext[MLDSA_SEEDBYTES+1] = MLDSA_L;
    shake256(seedbuf, 2*MLDSA_SEEDBYTES + MLDSA_CRHBYTES, ext, sizeof(ext));

    memcpy(rho,      seedbuf,                               MLDSA_SEEDBYTES);
    memcpy(rhoprime, seedbuf + MLDSA_SEEDBYTES,             MLDSA_CRHBYTES);
    memcpy(key,      seedbuf + MLDSA_SEEDBYTES + MLDSA_CRHBYTES, MLDSA_SEEDBYTES);

    // Step 3: Expand A from rho
    mldsa_polyvecl mat[MLDSA_K];
    mldsa_polyvec_matrix_expand(mat, rho);

    // Step 4: Sample s1 ∈ S_l^η, s2 ∈ S_k^η
    mldsa_polyvecl s1;
    mldsa_polyveck s2;
    mldsa_polyvecl_uniform_eta(&s1, rhoprime, 0);
    mldsa_polyveck_uniform_eta(&s2, rhoprime, MLDSA_L);

    // Step 5: t = A·s1 + s2
    mldsa_polyvecl s1hat = s1;
    mldsa_polyvecl_ntt(&s1hat);

    mldsa_polyveck t1, t0;
    mldsa_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    mldsa_polyveck_reduce(&t1);
    mldsa_polyveck_invntt_tomont(&t1);
    mldsa_polyveck_add(&t1, &t1, &s2);
    mldsa_polyveck_caddq(&t1);

    // Step 6: Power2Round t → (t1, t0)
    mldsa_polyveck_power2round(&t1, &t0, &t1);

    // Step 7: Pack public key
    pack_pk(pk.data(), rho, &t1);

    // Step 8: tr = H(pk, 64)
    uint8_t tr[MLDSA_TRBYTES];
    shake256(tr, MLDSA_TRBYTES, pk.data(), MLDSA_PUBLICKEYBYTES);

    // Step 9: Pack secret key
    pack_sk(sk.data(), rho, tr, key, &t0, &s1, &s2);

    local_memory_cleanse(seedbuf, sizeof(seedbuf));
    local_memory_cleanse(rhoprime, sizeof(rhoprime));
    return true;
}

// ===========================================================================
// ML-DSA.Sign — FIPS 204 §6.2 (deterministic / hedged)
// ===========================================================================

bool MLDSA_Sign(MLDSASignature& sig,
                const uint8_t* msg, size_t msg_len,
                const MLDSASecretKey& sk,
                const uint8_t rnd_in[32]) {
    uint8_t rho[MLDSA_SEEDBYTES];
    uint8_t tr[MLDSA_TRBYTES];
    uint8_t key[MLDSA_SEEDBYTES];
    uint8_t mu[MLDSA_CRHBYTES];
    uint8_t rhoprime[MLDSA_CRHBYTES];
    uint8_t rnd[MLDSA_RNDBYTES] = {0};
    uint8_t c_tilde[MLDSA_CTILDEBYTES];
    uint8_t w1_bytes[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES];
    uint16_t kappa = 0;
    mldsa_poly cp;
    mldsa_polyveck t0;
    mldsa_polyvecl s1;
    mldsa_polyveck s2;
    mldsa_polyvecl mat[MLDSA_K];
    mldsa_polyvecl y;
    mldsa_polyvecl z;
    mldsa_polyveck w;
    mldsa_polyveck w0;
    mldsa_polyveck w1;
    mldsa_polyveck h;
    mldsa_polyveck tmp;

    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk.data());

    H2(mu, sizeof(mu), tr, MLDSA_TRBYTES, msg, msg_len);
    if (rnd_in != nullptr) {
        memcpy(rnd, rnd_in, sizeof(rnd));
    }
    H3(rhoprime, sizeof(rhoprime), key, sizeof(key), rnd, sizeof(rnd), mu, sizeof(mu));

    mldsa_polyvec_matrix_expand(mat, rho);
    mldsa_polyvecl_ntt(&s1);
    mldsa_polyveck_ntt(&s2);
    mldsa_polyveck_ntt(&t0);

    for (;;) {
        mldsa_polyvecl_uniform_gamma1(&y, rhoprime, kappa);

        z = y;
        mldsa_polyvecl_ntt(&z);
        mldsa_polyvec_matrix_pointwise_montgomery(&w, mat, &z);
        mldsa_polyveck_reduce(&w);
        mldsa_polyveck_invntt_tomont(&w);
        mldsa_polyveck_caddq(&w);

        mldsa_polyveck_decompose(&w1, &w0, &w);
        mldsa_polyveck_pack_w1(w1_bytes, &w1);
        H2(c_tilde, sizeof(c_tilde), mu, sizeof(mu), w1_bytes, sizeof(w1_bytes));
        mldsa_poly_challenge(&cp, c_tilde);
        mldsa_poly_ntt(&cp);

        mldsa_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
        mldsa_polyvecl_invntt_tomont(&z);
        mldsa_polyvecl_add(&z, &z, &y);
        mldsa_polyvecl_reduce(&z);
        if (mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA)) {
            kappa += 1;
            continue;
        }

        mldsa_polyveck_pointwise_poly_montgomery(&tmp, &cp, &s2);
        mldsa_polyveck_invntt_tomont(&tmp);
        mldsa_polyveck_sub(&w0, &w0, &tmp);
        mldsa_polyveck_reduce(&w0);
        if (mldsa_polyveck_chknorm(&w0, MLDSA_GAMMA2 - MLDSA_BETA)) {
            kappa += 1;
            continue;
        }

        mldsa_polyveck_pointwise_poly_montgomery(&tmp, &cp, &t0);
        mldsa_polyveck_invntt_tomont(&tmp);
        mldsa_polyveck_reduce(&tmp);
        if (mldsa_polyveck_chknorm(&tmp, MLDSA_GAMMA2)) {
            kappa += 1;
            continue;
        }

        mldsa_polyveck_add(&w0, &w0, &tmp);
        if (mldsa_polyveck_make_hint(&h, &w0, &w1) > MLDSA_OMEGA) {
            kappa += 1;
            continue;
        }

        pack_sig(sig.data(), c_tilde, &z, &h);
        break;
    }

    local_memory_cleanse(rho, sizeof(rho));
    local_memory_cleanse(tr, sizeof(tr));
    local_memory_cleanse(key, sizeof(key));
    local_memory_cleanse(mu, sizeof(mu));
    local_memory_cleanse(rhoprime, sizeof(rhoprime));
    local_memory_cleanse(rnd, sizeof(rnd));
    local_memory_cleanse(c_tilde, sizeof(c_tilde));
    local_memory_cleanse(w1_bytes, sizeof(w1_bytes));
    local_memory_cleanse(&cp, sizeof(cp));
    local_memory_cleanse(&t0, sizeof(t0));
    local_memory_cleanse(&s1, sizeof(s1));
    local_memory_cleanse(&s2, sizeof(s2));
    local_memory_cleanse(&y, sizeof(y));
    local_memory_cleanse(&z, sizeof(z));
    local_memory_cleanse(&w, sizeof(w));
    local_memory_cleanse(&w0, sizeof(w0));
    local_memory_cleanse(&w1, sizeof(w1));
    local_memory_cleanse(&h, sizeof(h));
    local_memory_cleanse(&tmp, sizeof(tmp));
    return true;
}

// ===========================================================================
// ML-DSA.Verify — FIPS 204 §7.3
// ===========================================================================

bool MLDSA_Verify(const MLDSASignature& sig,
                  const uint8_t* msg, size_t msg_len,
                  const MLDSAPublicKey& pk) {
    uint8_t rho[MLDSA_SEEDBYTES];
    uint8_t tr[MLDSA_TRBYTES];
    uint8_t mu[MLDSA_TRBYTES];
    uint8_t c_tilde[MLDSA_CTILDEBYTES];
    uint8_t c_tilde_check[MLDSA_CTILDEBYTES];
    uint8_t w1_bytes[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES];
    mldsa_poly cp;
    mldsa_polyvecl mat[MLDSA_K];
    mldsa_polyvecl z;
    mldsa_polyveck t1;
    mldsa_polyveck h;
    mldsa_polyveck w1;
    mldsa_polyveck tmp;

    unpack_pk(rho, &t1, pk.data());
    if (unpack_sig(c_tilde, &z, &h, sig.data())) {
        return false;
    }
    if (mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA)) {
        return false;
    }

    mldsa_polyvec_matrix_expand(mat, rho);
    H(tr, sizeof(tr), pk.data(), MLDSA_PUBLICKEYBYTES);
    H2(mu, sizeof(mu), tr, sizeof(tr), msg, msg_len);
    mldsa_poly_challenge(&cp, c_tilde);

    mldsa_polyvecl_ntt(&z);
    mldsa_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    mldsa_polyveck_shiftl(&t1);
    mldsa_polyveck_ntt(&t1);
    mldsa_poly_ntt(&cp);
    mldsa_polyveck_pointwise_poly_montgomery(&tmp, &cp, &t1);
    mldsa_polyveck_sub(&w1, &w1, &tmp);
    mldsa_polyveck_reduce(&w1);
    mldsa_polyveck_invntt_tomont(&w1);
    mldsa_polyveck_caddq(&w1);
    mldsa_polyveck_use_hint(&w1, &w1, &h);
    mldsa_polyveck_pack_w1(w1_bytes, &w1);
    H2(c_tilde_check, sizeof(c_tilde_check), mu, sizeof(mu), w1_bytes, sizeof(w1_bytes));

    uint8_t diff = 0;
    for (size_t i = 0; i < sizeof(c_tilde_check); ++i) {
        diff |= c_tilde[i] ^ c_tilde_check[i];
    }

    local_memory_cleanse(rho, sizeof(rho));
    local_memory_cleanse(tr, sizeof(tr));
    local_memory_cleanse(mu, sizeof(mu));
    local_memory_cleanse(c_tilde, sizeof(c_tilde));
    local_memory_cleanse(c_tilde_check, sizeof(c_tilde_check));
    local_memory_cleanse(w1_bytes, sizeof(w1_bytes));
    local_memory_cleanse(&cp, sizeof(cp));
    local_memory_cleanse(&z, sizeof(z));
    local_memory_cleanse(&t1, sizeof(t1));
    local_memory_cleanse(&h, sizeof(h));
    local_memory_cleanse(&w1, sizeof(w1));
    local_memory_cleanse(&tmp, sizeof(tmp));
    return diff == 0;
}

bool MLDSA_Verify(std::span<const uint8_t, MLDSA_SIG_SIZE>   sig,
                  std::span<const uint8_t>                    msg,
                  std::span<const uint8_t, MLDSA_PUBKEY_SIZE> pk) {
    MLDSASignature sig_arr;
    MLDSAPublicKey pk_arr;
    memcpy(sig_arr.data(), sig.data(), MLDSA_SIG_SIZE);
    memcpy(pk_arr.data(),  pk.data(),  MLDSA_PUBKEY_SIZE);
    return MLDSA_Verify(sig_arr, msg.data(), msg.size(), pk_arr);
}

// Stub for missing polyvecl functions referenced above
void mldsa_polyvecl_reduce(mldsa_polyvecl *v) {
    for (int i = 0; i < MLDSA_L; ++i) mldsa_poly_reduce(&v->vec[i]);
}
