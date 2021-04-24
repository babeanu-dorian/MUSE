#include <iterator>

#include "pre/pre_scheme.h"
#include "pre/key_pair.h"
#include "pre/public_key.h"
#include "pre/secret_key.h"
#include "pre/reencryption_key.h"
#include "pre/primary_ctxt.h"
#include "pre/reencrypted_ctxt.h"

#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/sha.h"

namespace pre {

    CryptoPP::Integer PreScheme::hash(CryptoPP::Integer const &input, size_t bitSize) {
        // encode integer to byte vector
        std::vector<CryptoPP::byte> inputBytes;
        inputBytes.resize(input.MinEncodedSize());
        input.Encode(&inputBytes[0], inputBytes.size());

        // compute the SHA256 hash of the input
        CryptoPP::SHA256 hashFunc;
        hashFunc.Update(inputBytes.data(), inputBytes.size());
        std::vector<CryptoPP::byte> digest(hashFunc.DigestSize(), 0);
        hashFunc.Final(&digest[0]);

        // use the hash to key AES-CTR to obtain a hash of desired length
        CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption aes;
        static std::vector<CryptoPP::byte> const zeroIv(aes.IVSize(), 0);
        aes.SetKeyWithIV(digest.data(), digest.size(), zeroIv.data());
        size_t byteSize = bitSize / CHAR_BIT + (bitSize % CHAR_BIT == 0 ? 0 : 1);
        std::vector<CryptoPP::byte> zeroInput(byteSize);
        std::vector<CryptoPP::byte> outputBytes;
        CryptoPP::StringSource(zeroInput.data(), zeroInput.size(), true,
            new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::VectorSink(outputBytes)));

        // convert the hash into an integer
        CryptoPP::Integer result(outputBytes.data(), outputBytes.size());

        // truncate extra bits
        result >>= byteSize * CHAR_BIT - bitSize;

        return result;
    }

    CryptoPP::Integer PreScheme::hash(CryptoPP::Integer const &input, CryptoPP::Integer const &top) {
        return hash(input, top.BitCount()) % top;
    }

    CryptoPP::Integer PreScheme::integerConcat(std::vector<CryptoPP::Integer> args) {
        CryptoPP::Integer result;
        for (auto it = std::cbegin(args); it != std::cend(args); ++it) {
            size_t bitCount = it->BitCount();
            result <<= (bitCount == 0 ? 1 : bitCount);
            result += *it;
        }
        return result;
    }

    CryptoPP::Integer PreScheme::generateSafePrime(CryptoPP::AutoSeededRandomPool &rng, size_t bitSize) {
        CryptoPP::Integer x, p;
        CryptoPP::AlgorithmParameters params = CryptoPP::MakeParameters("BitLength", (int) bitSize - 1)("RandomNumberType", CryptoPP::Integer::PRIME);
        do {
            x.GenerateRandom(rng, params);
            p = x;
            p *= 2;
            ++p;
        } while (!CryptoPP::IsPrime(p));
        return p;
    }

    PreScheme::PreScheme(size_t k1, size_t k2, size_t kp):
        _k1(k1),
        _k2(k2),
        _kp(kp)
    {}

    KeyPair PreScheme::keyGen() {

        // p and q are safe primes of _kp bits
        CryptoPP::Integer p(generateSafePrime(_rng, _kp));
        CryptoPP::Integer q(generateSafePrime(_rng, _kp));

        // rMod = p * (p - 1) * q * (q - 1) / 4
        CryptoPP::Integer rMod(p);
        rMod *= p - CryptoPP::Integer::One();
        rMod *= q;
        rMod *= q - CryptoPP::Integer::One();
        rMod /= 4;

        SecretKey sk(
            p,
            q,
            CryptoPP::Integer(_rng, CryptoPP::Integer::One(), rMod),
            CryptoPP::Integer(_rng, CryptoPP::Integer::One(), rMod),
            rMod
        ); // a, b random in [1, rMod]

        // N = p * q
        CryptoPP::Integer N(p);
        N *= q;

        // squaredN = N ^ 2
        CryptoPP::Integer squaredN(N);
        squaredN *= squaredN;
        
        // alpha random in [1, N ^ 2)
        CryptoPP::Integer alpha(_rng, CryptoPP::Integer::One(), squaredN - 1);

        // g0 = (alpha ^ 2) % (N ^ 2)
        CryptoPP::Integer g0(a_times_b_mod_c(alpha, alpha, squaredN));

        PublicKey pk(
            N,
            g0,
            a_exp_b_mod_c(g0, sk.a(), squaredN),    // g1 = (g0 ^ a) % (N ^ 2)
            a_exp_b_mod_c(g0, sk.b(), squaredN)     // g2 = (g0 ^ b) % (N ^ 2)
        );

        return KeyPair(pk, sk);
    }

    ReencryptionKey PreScheme::reKeyGen(SecretKey const &skx, PublicKey const &pky) {
        CryptoPP::Integer sigma(_rng, CryptoPP::Integer::Zero(), pky.N() - CryptoPP::Integer::One());
        CryptoPP::Integer beta(_rng, _k1);

        // r = H(sigma || beta, N_y ^ 2)
        CryptoPP::Integer r(hash(integerConcat({sigma, beta}), pky.squaredN()));

        // b = 1 + sigma * N_y
        CryptoPP::Integer b(sigma);
        b *= pky.N();
        ++b;

        // rk.C = H(sigma, 2 ^ _k1) XOR beta
        CryptoPP::Integer C(hash(sigma, _k1));
        C ^= beta;

        // rk.R = (a_x - beta) % (p_x * q_x * p'_x * q'_x)
        CryptoPP::Integer R(skx.a());
        R -= beta;
        while (R.IsNegative()) {
            R += skx.rMod();
        }
        R %= skx.rMod();

        return ReencryptionKey(
            // rk.A = (g0_y ^ r) % (N_y ^ 2)
            a_exp_b_mod_c(pky.g0(), r, pky.squaredN()),
            // rk.B = (g2_y ^ r) * (1 + sigma * N_y) % (N_y ^ 2)
            a_times_b_mod_c(b, a_exp_b_mod_c(pky.g2(), r, pky.squaredN()), pky.squaredN()),
            C,
            R
        );
    }
    
    PrimaryCtxt PreScheme::encrypt(CryptoPP::Integer const &m, PublicKey const &pk) {

        CryptoPP::Integer sigma(_rng, CryptoPP::Integer::Zero(), pk.N() - CryptoPP::Integer::One());

        // r = H(sigma || m, N ^ 2)
        CryptoPP::Integer r(hash(integerConcat({sigma, m}), pk.squaredN()));

        // A = (g0 ^ r) % (N ^ 2)
        CryptoPP::Integer A(a_exp_b_mod_c(pk.g0(), r, pk.squaredN()));

        // B = g1 ^ r * (1 + sigma * N) % (N ^ 2)
        CryptoPP::Integer B(sigma);
        B *= pk.N();
        ++B;
        B = a_times_b_mod_c(B, a_exp_b_mod_c(pk.g1(), r, pk.squaredN()), pk.squaredN());

        size_t mBitCount = m.BitCount();

        // C = H(sigma, 2 ^ mBitCount) XOR m
        CryptoPP::Integer C(hash(sigma, mBitCount));
        C ^= m;

        // D = (g2 ^ r) % (N ^ 2)
        CryptoPP::Integer D(a_exp_b_mod_c(pk.g2(), r, pk.squaredN()));

        // t random value with ((N ^ 2).BitCount() + _k2) bits
        CryptoPP::Integer t(_rng, pk.squaredN().BitCount() + _k2);

        // c = H(A || D || g0 || g2 || g0 ^ t || g2 ^ t || B || C, 2 ^ _k2)
        CryptoPP::Integer c(hash(integerConcat({
            A, D, pk.g0(), pk.g2(),
            a_exp_b_mod_c(pk.g0(), t, pk.squaredN()),
            a_exp_b_mod_c(pk.g2(), t, pk.squaredN()),
            B, C
        }), _k2));

        // s = t - c * r
        CryptoPP::Integer s(t);
        s -= c * r;

        return PrimaryCtxt(mBitCount, pk, A, B, C, D, c, s);
    }
    
    ReencryptedCtxt PreScheme::reencrypt(PrimaryCtxt const &ctxt, ReencryptionKey const &rk) {
        
        ctxt.validate(*this);

        return ReencryptedCtxt(
            ctxt.ptxtBitSize(),
            ctxt.pk(),
            ctxt.A(),
            rk.A(),
            a_exp_b_mod_c(ctxt.A(), rk.R(), ctxt.pk().squaredN()),
            ctxt.B(),
            rk.B(),
            ctxt.C(),
            rk.C()
        );
    }
    
    CryptoPP::Integer PreScheme::decrypt(Ctxt const &ctxt, PublicKey const &pk, SecretKey const &sk) {
        return ctxt.decrypt(*this, pk, sk);
    }
}