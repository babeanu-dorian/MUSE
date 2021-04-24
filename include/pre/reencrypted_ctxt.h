#ifndef PRE_REENCRYPTED_CTXT_H
#define PRE_REENCRYPTED_CTXT_H

#include "pre/ctxt.h"

namespace pre {
    class ReencryptedCtxt : public Ctxt {
        
        CryptoPP::Integer const _A1;
        CryptoPP::Integer const _A2;
        CryptoPP::Integer const _A3;
        CryptoPP::Integer const _B1;
        CryptoPP::Integer const _B2;
        CryptoPP::Integer const _C1;
        CryptoPP::Integer const _C2;

        public:
            ReencryptedCtxt(size_t ptxtBitSize, PublicKey const &pk,
                            CryptoPP::Integer const &A1, CryptoPP::Integer const &A2, CryptoPP::Integer const &A3,
                            CryptoPP::Integer const &B1, CryptoPP::Integer const &B2,
                            CryptoPP::Integer const &C1, CryptoPP::Integer const &C2);

            CryptoPP::Integer const &A1() const;
            CryptoPP::Integer const &A2() const;
            CryptoPP::Integer const &A3() const;
            CryptoPP::Integer const &B1() const;
            CryptoPP::Integer const &B2() const;
            CryptoPP::Integer const &C1() const;
            CryptoPP::Integer const &C2() const;
        
        private:
            CryptoPP::Integer decryptImpl(PreScheme const &pre, PublicKey const &pk, SecretKey const &sk) const override;
    };
}

#endif /* !PRE_REENCRYPTED_CTXT_H */