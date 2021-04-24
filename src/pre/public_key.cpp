#include "pre/public_key.h"

namespace pre {
    PublicKey::PublicKey(CryptoPP::Integer const &N, CryptoPP::Integer const &g0,
                         CryptoPP::Integer const &g1, CryptoPP::Integer const &g2):
        _N(N),
        _squaredN(N.Squared()),
        _g0(g0),
        _g1(g1),
        _g2(g2)
    {}
            
    CryptoPP::Integer const &PublicKey::N() const {
        return _N;
    }

    CryptoPP::Integer const &PublicKey::squaredN() const {
        return _squaredN;
    }
    
    CryptoPP::Integer const &PublicKey::g0() const {
        return _g0;
    }
    
    CryptoPP::Integer const &PublicKey::g1() const {
        return _g1;
    }
    
    CryptoPP::Integer const &PublicKey::g2() const {
        return _g2;
    }
    
}
