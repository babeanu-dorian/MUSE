#ifndef PRE_KEY_PAIR_H
#define PRE_KEY_PAIR_H

#include "pre/public_key.h"
#include "pre/secret_key.h"

namespace pre {
    class KeyPair {
        PublicKey const _pk;
        SecretKey const _sk;

        public:
            KeyPair(PublicKey const &pk, SecretKey const &sk);
            
            PublicKey const &pk() const;
            SecretKey const &sk() const;
    };
}

#endif /* !PRE_KEY_PAIR_H */