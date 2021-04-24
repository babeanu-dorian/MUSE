#ifndef PRE_SECRET_KEY_H
#define PRE_SECRET_KEY_H

#include "cryptopp/integer.h"

namespace pre {
    class SecretKey {
        CryptoPP::Integer const _p;
        CryptoPP::Integer const _q;
        CryptoPP::Integer const _a;
        CryptoPP::Integer const _b;
        CryptoPP::Integer const _rMod;

        public:
            SecretKey(CryptoPP::Integer const &p, CryptoPP::Integer const &q, CryptoPP::Integer const &a,
                      CryptoPP::Integer const &b, CryptoPP::Integer const &rMod);
            
            CryptoPP::Integer const &p() const;
            CryptoPP::Integer const &q() const;
            CryptoPP::Integer const &a() const;
            CryptoPP::Integer const &b() const;
            CryptoPP::Integer const &rMod() const;
    };
}

#endif /* !PRE_SECRET_KEY_H */