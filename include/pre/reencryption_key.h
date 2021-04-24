#ifndef PRE_REENCRYPTION_KEY_H
#define PRE_REENCRYPTION_KEY_H

#include "cryptopp/integer.h"

namespace pre {
    class ReencryptionKey {
        CryptoPP::Integer const _A;
        CryptoPP::Integer const _B;
        CryptoPP::Integer const _C;
        CryptoPP::Integer const _R;

        public:
            ReencryptionKey(CryptoPP::Integer const &A, CryptoPP::Integer const &B,
                      CryptoPP::Integer const &C, CryptoPP::Integer const &R);
            
            CryptoPP::Integer const &A() const;
            CryptoPP::Integer const &B() const;
            CryptoPP::Integer const &C() const;
            CryptoPP::Integer const &R() const;
    };
}

#endif /* !PRE_REENCRYPTION_KEY_H */