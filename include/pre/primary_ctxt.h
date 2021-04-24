#ifndef PRE_PRIMARY_CTXT_H
#define PRE_PRIMARY_CTXT_H

#include "pre/ctxt.h"

namespace pre {

    class PrimaryCtxt : public Ctxt {

        CryptoPP::Integer const _A;
        CryptoPP::Integer const _B;
        CryptoPP::Integer const _C;
        CryptoPP::Integer const _D;
        CryptoPP::Integer const _c;
        CryptoPP::Integer const _s;

        public:
            PrimaryCtxt(size_t ptxtBitSize, PublicKey const &pk,
                        CryptoPP::Integer const &A, CryptoPP::Integer const &B,
                        CryptoPP::Integer const &C, CryptoPP::Integer const &D,
                        CryptoPP::Integer const &c, CryptoPP::Integer const &s);
            
            CryptoPP::Integer const &A() const;
            CryptoPP::Integer const &B() const;
            CryptoPP::Integer const &C() const;
            CryptoPP::Integer const &D() const;
            CryptoPP::Integer const &c() const;
            CryptoPP::Integer const &s() const;

            void validate(PreScheme const &pre) const;
        
        private:
            CryptoPP::Integer decryptImpl(PreScheme const &pre, PublicKey const &pk, SecretKey const &sk) const override;
    };
}

#endif /* !PRE_PRIMARY_CTXT_H */