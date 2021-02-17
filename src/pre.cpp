#include "pre.h"

namespace pre {

    PreScheme::PreScheme(size_t n, size_t k1, size_t k2):
        _n(n),
        _k1(k1),
        _k2(k2)
    {}

    NTL::ZZ PreScheme::random(NTL::ZZ const &top) { // TODO
        return NTL::ZZ(0l);
    }

    std::vector<bit> PreScheme::hash(std::vector<bit> const &input, size_t length) { // TODO
        return std::vector<bit>(length, 0);
    }

    KeyPair PreScheme::keyGen() {

    }

    ReEncryptionKey PreScheme::reKeyGen(SecretKey const &skx, PublicKey const &pky) {

    }
    
    Ctxt PreScheme::encrypt(std::vector<bit> const &m, PublicKey const &pk) {

    }
    
    Ctxt PreScheme::reencrypt(Ctxt const &ctxt, PublicKey const &pk, ReEncryptionKey const &rk) {

    }
    
    std::vector<bit> PreScheme::decrypt(Ctxt const &ctxt, PublicKey const &pk, SecretKey const &sk) {

    }
}