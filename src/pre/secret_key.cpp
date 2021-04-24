#include "pre/secret_key.h"

namespace pre {
    SecretKey::SecretKey(CryptoPP::Integer const &p, CryptoPP::Integer const &q, CryptoPP::Integer const &a,
                         CryptoPP::Integer const &b, CryptoPP::Integer const &rMod):
        _p(p),
        _q(q),
        _a(a),
        _b(b),
        _rMod(rMod)
    {}
            
    CryptoPP::Integer const &SecretKey::p() const {
        return _p;
    }

    CryptoPP::Integer const &SecretKey::q() const {
        return _q;
    }

    CryptoPP::Integer const &SecretKey::a() const {
        return _a;
    }

    CryptoPP::Integer const &SecretKey::b() const {
        return _b;
    }

    CryptoPP::Integer const &SecretKey::rMod() const {
        return _rMod;
    }
}