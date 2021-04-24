#ifndef PRE_PUBLIC_KEY_H
#define PRE_PUBLIC_KEY_H

#include "cryptopp/integer.h"

namespace pre {
    class PublicKey {
        CryptoPP::Integer const _N;
        CryptoPP::Integer const _squaredN;
        CryptoPP::Integer const _g0;
        CryptoPP::Integer const _g1;
        CryptoPP::Integer const _g2;

        public:
            PublicKey(CryptoPP::Integer const &N, CryptoPP::Integer const &g0,
                      CryptoPP::Integer const &g1, CryptoPP::Integer const &g2);
            
            CryptoPP::Integer const &N() const;
            CryptoPP::Integer const &squaredN() const;
            CryptoPP::Integer const &g0() const;
            CryptoPP::Integer const &g1() const;
            CryptoPP::Integer const &g2() const;
    };
}

#endif /* !PRE_PUBLIC_KEY_H */