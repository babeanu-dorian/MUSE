#include "pre/primary_ctxt.h"
#include "pre/pre_scheme.h"
#include "pre/public_key.h"
#include "pre/secret_key.h"

namespace pre {
    PrimaryCtxt::PrimaryCtxt(size_t ptxtBitSize, PublicKey const &pk,
                             CryptoPP::Integer const &A, CryptoPP::Integer const &B,
                             CryptoPP::Integer const &C, CryptoPP::Integer const &D,
                             CryptoPP::Integer const &c, CryptoPP::Integer const &s):
        Ctxt(ptxtBitSize, pk),
        _A(A),
        _B(B),
        _C(C),
        _D(D),
        _c(c),
        _s(s)
    {}
            
    CryptoPP::Integer const &PrimaryCtxt::A() const {
        return _A;
    }

    CryptoPP::Integer const &PrimaryCtxt::B() const {
        return _B;
    }
    
    CryptoPP::Integer const &PrimaryCtxt::C() const {
        return _C;
    }
    
    CryptoPP::Integer const &PrimaryCtxt::D() const {
        return _D;
    }
    
    CryptoPP::Integer const &PrimaryCtxt::c() const {
        return _c;
    }
    
    CryptoPP::Integer const &PrimaryCtxt::s() const {
        return _s;
    }

    void PrimaryCtxt::validate(PreScheme const &pre) const {
        CryptoPP::Integer sAbs(_s.AbsoluteValue());

        // validC = H(A || D || g0 || g2 || (g0 ^ s) * (A ^ c) || (g2 ^ s) * (D ^ c) || B || C, 2 ^ _k2)
        CryptoPP::Integer validC(PreScheme::hash(PreScheme::integerConcat({
            _A, _D, pk().g0(), pk().g2(),
            a_times_b_mod_c(
                (_s < 0 ?  // a_exp_b_mod_c cannot handle negative exponents
                    a_exp_b_mod_c(pk().g0().InverseMod(pk().squaredN()), sAbs, pk().squaredN()) :
                    a_exp_b_mod_c(pk().g0(), _s, pk().squaredN())
                ),
                a_exp_b_mod_c(_A, _c, pk().squaredN()),
                pk().squaredN()
            ),
            a_times_b_mod_c(
                (_s < 0 ?  // a_exp_b_mod_c cannot handle negative exponents
                    a_exp_b_mod_c(pk().g2().InverseMod(pk().squaredN()), sAbs, pk().squaredN()) :
                    a_exp_b_mod_c(pk().g2(), _s, pk().squaredN())
                ),
                a_exp_b_mod_c(_D, _c, pk().squaredN()),
                pk().squaredN()
            ),
            _B, _C
        }), pre._k2));

        if (_c != validC) {
            throw Ctxt::INVALID_CTXT_ERROR;
        }
    }
        
    CryptoPP::Integer PrimaryCtxt::decryptImpl(PreScheme const &pre, PublicKey const &pk, SecretKey const &sk) const {
        validate(pre);

        // sigma = (B / (A^a) - 1) % (N ^ 2) / N
        CryptoPP::Integer sigma(a_times_b_mod_c(
            _B,
            a_exp_b_mod_c(_A, sk.a(), this->pk().squaredN()).InverseMod(this->pk().squaredN()),
            this->pk().squaredN()
        ));
        --sigma;
        sigma /= this->pk().N();

        // m = C XOR H(sigma, 2 ^ ptxtBitSize)
        CryptoPP::Integer m(PreScheme::hash(sigma, ptxtBitSize()));
        m ^= _C;

        // testB = (g1 ^ H(sigma || m, N ^ 2)) * (1 + sigma * N) % (N ^ 2)
        CryptoPP::Integer testB(sigma);
        testB *= this->pk().N();
        ++testB;
        testB = a_times_b_mod_c(
            testB,
            a_exp_b_mod_c(
                this->pk().g1(),
                PreScheme::hash(PreScheme::integerConcat({sigma, m}), this->pk().squaredN()),
                this->pk().squaredN()
            ),
            this->pk().squaredN()
        );

        if (_B != testB) {
            throw Ctxt::INVALID_CTXT_ERROR;
        }

        return m;
    }
}