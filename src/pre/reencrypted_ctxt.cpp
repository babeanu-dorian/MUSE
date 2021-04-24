#include "pre/reencrypted_ctxt.h"
#include "pre/pre_scheme.h"
#include "pre/secret_key.h"

namespace pre {
    ReencryptedCtxt::ReencryptedCtxt(size_t ptxtBitSize, PublicKey const &pk,
                                     CryptoPP::Integer const &A1, CryptoPP::Integer const &A2, CryptoPP::Integer const &A3,
                                     CryptoPP::Integer const &B1, CryptoPP::Integer const &B2,
                                     CryptoPP::Integer const &C1, CryptoPP::Integer const &C2):
        Ctxt(ptxtBitSize, pk),
        _A1(A1),
        _A2(A2),
        _A3(A3),
        _B1(B1),
        _B2(B2),
        _C1(C1),
        _C2(C2)
    {}

    CryptoPP::Integer const &ReencryptedCtxt::A1() const {
        return _A1;
    }

    CryptoPP::Integer const &ReencryptedCtxt::A2() const {
        return _A2;
    }

    CryptoPP::Integer const &ReencryptedCtxt::A3() const {
        return _A3;
    }

    CryptoPP::Integer const &ReencryptedCtxt::B1() const {
        return _B1;
    }

    CryptoPP::Integer const &ReencryptedCtxt::B2() const {
        return _B2;
    }

    CryptoPP::Integer const &ReencryptedCtxt::C1() const {
        return _C1;
    }

    CryptoPP::Integer const &ReencryptedCtxt::C2() const {
        return _C2;
    }

    CryptoPP::Integer ReencryptedCtxt::decryptImpl(PreScheme const &pre, PublicKey const &pk, SecretKey const &sk) const {
        // sigma2 = (B2 / (A2 ^ b) - 1) % (N ^ 2) / N
        CryptoPP::Integer sigma2(a_times_b_mod_c(
            _B2,
            a_exp_b_mod_c(_A2, sk.b(), pk.squaredN()).InverseMod(pk.squaredN()),
            pk.squaredN()
        ));
        --sigma2;
        sigma2 /= pk.N();

        // beta = C2 XOR H(sigma2, k1)
        CryptoPP::Integer beta(PreScheme::hash(sigma2, pre._k1));
        beta ^= _C2;

        // testB2 = (g1 ^ H(sigma2 || beta, N ^ 2)) * (1 + sigma2 * N) % (N ^ 2)
        CryptoPP::Integer testB2(sigma2);
        testB2 *= pk.N();
        ++testB2;
        testB2 = a_times_b_mod_c(
            testB2,
            a_exp_b_mod_c(
                pk.g2(),
                PreScheme::hash(PreScheme::integerConcat({sigma2, beta}), pk.squaredN()),
                pk.squaredN()
            ),
            pk.squaredN()
        );

        if (_B2 != testB2) {
            throw Ctxt::INVALID_CTXT_ERROR;
        }

        // sigma1 = (B1 / (A3 * (A1 ^ beta)) - 1) % (sourcePk.N ^ 2) / sourcePk.N
        CryptoPP::Integer sigma1(a_times_b_mod_c(
            _B1,
            a_times_b_mod_c(
                _A3,
                a_exp_b_mod_c(_A1, beta, this->pk().squaredN()),
                this->pk().squaredN()
            ).InverseMod(this->pk().squaredN()),
            this->pk().squaredN()
        ));
        --sigma1;
        sigma1 /= this->pk().N();

        // m = C1 XOR H(sigma1, 2 ^ ptxtBitSize)
        CryptoPP::Integer m(PreScheme::hash(sigma1, ptxtBitSize()));
        m ^= _C1;

        // testB1 = (sourcePk.g1 ^ H(sigma1 || m, sourcePk.N ^ 2)) * (1 + sigma1 * sourcePk.N) % (sourcePk.N ^ 2)
        CryptoPP::Integer testB1(sigma1);
        testB1 *= this->pk().N();
        ++testB1;
        testB1 = a_times_b_mod_c(
            testB1,
            a_exp_b_mod_c(
                this->pk().g1(),
                PreScheme::hash(PreScheme::integerConcat({sigma1, m}), this->pk().squaredN()),
                this->pk().squaredN()
            ),
            this->pk().squaredN()
        );

        if (_B1 != testB1) {
            throw Ctxt::INVALID_CTXT_ERROR;
        }

        return m;
    }
}