#include "pre/key_pair.h" 

namespace pre {
    KeyPair::KeyPair(PublicKey const &pk, SecretKey const &sk):
        _pk(pk),
        _sk(sk)
    {}
            
    PublicKey const &KeyPair::pk() const {
        return _pk;
    }

    SecretKey const &KeyPair::sk() const {
        return _sk;
    }
}