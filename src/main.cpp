#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>
#include <cmath>

#include "XKCP/SP800-185.h"
#include "helib/helib.h"
#include "helib/binaryArith.h"
#include "helib/intraSlot.h"

typedef uint8_t byte;
typedef bool bit;

class HeContext {

    helib::Context const _context;
    helib::SecKey const _sk;
    helib::PubKey const &_pk;
    helib::Ptxt<helib::BGV> const _ptxt0;
    helib::Ptxt<helib::BGV> const _ptxt1;

    public:
        HeContext():
            _context(contextInit()),
            _sk(secretKeyInit(_context)),
            _pk(_sk),
            _ptxt0(_context),
            _ptxt1(_context, NTL::ZZX(1l))
        {}

    helib::Ctxt encrypt(bit b) const {
        helib::Ptxt<helib::BGV> const &ptxt = (b ? _ptxt1 : _ptxt0);
        helib::Ctxt ctxt(_pk);
        _pk.Encrypt(ctxt, ptxt);
        return ctxt;
    }
/*
    std::vector<helib::Ctxt> encrypt(std::string const &ptxt) const {
        std::vector<helib::Ctxt> ctxt;
        ctxt.reserve(ptxt.size() * CHAR_BIT);
        for (auto &c : ptxt) {
            for(size_t i = 0; i != CHAR_BIT; ++i) {
                ctxt.push_back(encrypt((c >> i) & 1));
            }
        }
        return ctxt;
    }
*/
    bit decrypt(helib::Ctxt const &ctxt) const {
        helib::Ptxt<helib::BGV> ptxt(_context);
        _sk.Decrypt(ptxt, ctxt);
        return ptxt == _ptxt1;
    }
/*
    std::string decrypt(std::vector<helib::Ctxt> const &ctxt) const {
        size_t ptxtSize = ctxt.size() / CHAR_BIT;
        std::string ptxt;
        ptxt.reserve(ptxtSize);
        for (size_t i = 0; i != ptxtSize; ++i) {
            char c = 0;
            for (size_t j = 0; j != CHAR_BIT; ++j) {
                c |= decrypt(ctxt[i * CHAR_BIT + j]) << j;
            }
            ptxt.push_back(c);
        }
        return ptxt;
    }
*/
    private:
        static helib::Context contextInit() {
            // Plaintext prime modulus.
            long p = 2;
            // Cyclotomic polynomial - defines phi(m).
            long m = 4095;
            // Hensel lifting (default = 1).
            long r = 1;
            // Number of bits of the modulus chain.
            long bits = 500;
            // Number of columns of Key-Switching matrix (typically 2 or 3).
            long c = 2;
            // Factorisation of m required for bootstrapping.
            std::vector<long> mvec = {7, 5, 9, 13};
            // Generating set of Zm* group.
            std::vector<long> gens = {2341, 3277, 911};
            // Orders of the previous generators.
            std::vector<long> ords = {6, 4, 6};

            std::cout << "Initialising context object..." << std::endl;
            // Initialize the context.
            helib::Context context(m, p, r, gens, ords);

            // Modify the context, adding primes to the modulus chain.
            std::cout << "Building modulus chain..." << std::endl;
            buildModChain(context, bits, c);

            // Make bootstrappable.
            context.makeBootstrappable(
                helib::convert<NTL::Vec<long>, std::vector<long>>(mvec));

            // Print the context.
            context.zMStar.printout();
            std::cout << std::endl;

            // Print the security level.
            std::cout << "Security: " << context.securityLevel() << std::endl;

            return context;
        }

        static helib::SecKey secretKeyInit(helib::Context const &context) {
            // Create a secret key associated with the context.
            helib::SecKey sk(context);
            // Generate the secret key.
            sk.GenSecKey();

            // Generate bootstrapping data.
            sk.genRecryptData();

            return sk;

            // Public key management.
            // Set the secret key (upcast: SecKey is a subclass of PubKey).
            // const helib::PubKey& public_key = secret_key;
        }
};

std::array<bit, 8> enc8(byte x) {
    std::array<bit, 8> encodedByte;
    for(size_t i = 0; i != CHAR_BIT; ++i) {
        encodedByte[i] = (x >> i) & 1;
    }
    return encodedByte;
}

std::vector<bit> rightEncode(size_t x) {
    std::vector<bit> encX;
    do {
        auto encodedByte = enc8(x & 0xFF);
        encX.insert(std::end(encX), std::crbegin(encodedByte), std::crend(encodedByte));
        x >>= CHAR_BIT;
    } while (x != 0);
    std::reverse(std::begin(encX), std::end(encX));
    auto encodedSize = enc8(encX.size() / CHAR_BIT);
    encX.insert(std::end(encX), std::cbegin(encodedSize), std::cend(encodedSize));
    return encX;
}

std::vector<bit> leftEncode(size_t x) {
    std::vector<bit> encX;
    do {
        auto encodedByte = enc8(x & 0xFF);
        encX.insert(std::end(encX), std::crbegin(encodedByte), std::crend(encodedByte));
        x >>= CHAR_BIT;
    } while (x != 0);
    auto encodedSize = enc8(encX.size() / CHAR_BIT);
    encX.insert(std::end(encX), std::crbegin(encodedSize), std::crend(encodedSize));
    std::reverse(std::begin(encX), std::end(encX));
    return encX;
}

std::vector<bit> makeBitString(std::string const &s) {
    std::vector<bit> bits(s.size() * CHAR_BIT, 0);
    size_t bitIdx = -1;
    for (auto &c : s) {
        for(size_t i = CHAR_BIT; i != 0; --i) {
            bits[++bitIdx] = (c >> (i- 1)) & 1;
        }
    }
    return bits;
}

std::vector<uint8_t> makeStringFromBits(std::vector<bit> const &bits) {
    std::vector<uint8_t> s(bits.size() / CHAR_BIT, 0);
    size_t bitIdx = -1;
    for (auto sIt = s.begin(); sIt != s.end(); ++sIt) {
        for(size_t i = 0; i != CHAR_BIT; ++i) {
            *sIt = ((*sIt) << 1) + bits[++bitIdx];
        }
    }
    return s;
}

std::vector<helib::Ctxt> encryptBitString(std::vector<bit> const &s, HeContext const &heContext) {
    std::vector<helib::Ctxt> ctxt;
    ctxt.reserve(s.size());
    std::transform(std::cbegin(s), std::cend(s), std::back_inserter(ctxt),
        std::bind(&HeContext::encrypt, &heContext, std::placeholders::_1));
    return ctxt;
}

std::vector<helib::Ctxt> encryptString(std::string const &s, HeContext const &heContext) {
    return encryptBitString(makeBitString(s), heContext);
}

std::vector<bit> decryptBitString(std::vector<helib::Ctxt> const &ctxt, HeContext const &heContext) {
    std::vector<bit> ptxt;
    ptxt.reserve(ctxt.size());
    std::transform(std::cbegin(ctxt), std::cend(ctxt), std::back_inserter(ptxt),
        std::bind(&HeContext::decrypt, &heContext, std::placeholders::_1));
    return ptxt;
}

std::vector<uint8_t> decryptString(std::vector<helib::Ctxt> const &s, HeContext const &heContext) {
    return makeStringFromBits(decryptBitString(s, heContext));
}

std::vector<helib::Ctxt> encodeString(std::vector<helib::Ctxt> const &s, HeContext const &heContext) {
    std::vector<helib::Ctxt> encodedS = encryptBitString(leftEncode(s.size()), heContext);
    encodedS.insert(std::end(encodedS), std::cbegin(s), std::cend(s));
    return encodedS;
}

std::vector<helib::Ctxt> encodeString(std::string const &s, HeContext const &heContext) {
    return encodeString(encryptString(s, heContext), heContext);
}

std::vector<helib::Ctxt> bytepad(std::vector<helib::Ctxt> const &s, size_t w, HeContext const &heContext) {
    std::vector<helib::Ctxt> result = encryptBitString(leftEncode(s.size()), heContext);
    result.insert(std::end(result), std::cbegin(s), std::cend(s));
    size_t pad = CHAR_BIT - (result.size() % CHAR_BIT);
    pad += (w - (((result.size() + pad) / CHAR_BIT) % w)) * CHAR_BIT;
    result.insert(std::cend(result), pad, heContext.encrypt(0));
    return result;
}

std::vector<helib::Ctxt> operator||(std::vector<helib::Ctxt> const &lhs, std::vector<helib::Ctxt> const &rhs) {
    std::vector<helib::Ctxt> result;
    result.reserve(lhs.size() + rhs.size());
    result.insert(std::end(result), std::cbegin(lhs), std::cend(lhs));
    result.insert(std::end(result), std::cbegin(rhs), std::cend(rhs));
    return result;
}

// Translates a collection of indices that indicate an element in an N-dimentsional vetor,
// into the index of said element in a 1-dimensional representation of the vector.
// Template arguments:
//     N - number of dimensions
// Parameters:
//     coords - element index in N-dimensional representation
//     dims   - list of dimensions sizes (i.e. 0 <= coords[i + i] < dims[i], for all 0 <= i < N - 1)
// Returns: element index in 1-dimensional representation
template <size_t N>
size_t singleIndex(std::array<size_t, N> const &coords, std::array<size_t, N - 1> const &dims) {
    size_t idx = coords[0];
    for (size_t i = 0; i != N - 1; ++i) {
        idx = idx * dims[i] + coords[i + 1];
    }
    return idx;
}

void theta(std::vector<helib::Ctxt> &S, size_t zSize, HeContext const &heContext) {
    size_t const xSize = 5, ySize = 5;
    std::array<size_t, 2> dims{ySize, zSize};
    std::vector<helib::Ctxt> C(ySize * zSize, heContext.encrypt(0));
    for (size_t x = 0; x != xSize; ++x) {
        for (size_t y = 0; y != ySize; ++y) {
            for (size_t z = 0; z != zSize; ++z) {
                size_t cIdx = singleIndex<2>({x, z}, {zSize});
                size_t sIdx = singleIndex<3>({y, x, z}, dims);
                C[cIdx] += S[sIdx];
            }
        }
    }
    for (size_t x = 0; x != xSize; ++x) {
        for (size_t y = 0; y != ySize; ++y) {
            for (size_t z = 0; z != zSize; ++z) {
                size_t cIdx1 = singleIndex<2>({(x - 1) % xSize, z}, {zSize});
                size_t cIdx2 = singleIndex<2>({(x + 1) % xSize, (z - 1) % zSize}, {zSize});
                size_t sIdx = singleIndex<3>({y, x, z}, dims);
                S[sIdx] += C[cIdx1];
                S[sIdx] += C[cIdx2];
            }
        }
    }
}

void ro(std::vector<helib::Ctxt> &S, size_t zSize, HeContext const &heContext) {
    size_t const tSize = 24;
    size_t const ySize = 5;
    std::array<size_t, 2> dims{5, zSize};
    size_t x = 1;
    size_t y = 0;
    std::vector<helib::Ctxt> lane(zSize, heContext.encrypt(0));
    for (size_t t = 0; t != tSize; ++t) {
        for (size_t z = 0; z != zSize; ++z) {
            size_t readIdx = singleIndex<3>({y, x, (z - (t + 1) * (t + 2) / 2) % zSize}, dims);
            lane[z] = S[readIdx];
        }
        for (size_t z = 0; z != zSize; ++z) {
            size_t writeIdx = singleIndex<3>({y, x, z}, dims);
            S[writeIdx] = lane[z];
        }
        size_t oldY = y;
        y = (2 * x + 3 * y) % ySize;
        x = oldY;
    }
}

void pi(std::vector<helib::Ctxt> &S, size_t zSize) {
    size_t const xSize = 5, ySize = 5;
    std::array<size_t, 2> dims{ySize, zSize};
    std::vector<helib::Ctxt> oldS(S);
    for (size_t x = 0; x != xSize; ++x) {
        for (size_t y = 0; y != ySize; ++y) {
            for (size_t z = 0; z != zSize; ++z) {
                size_t readIdx = singleIndex<3>({x, (x + 3 * y) % xSize, z}, dims);
                size_t writeIdx = singleIndex<3>({y, x, z}, dims);
                S[writeIdx] = oldS[readIdx];
            }
        }
    }
}

void chi(std::vector<helib::Ctxt> &S, size_t zSize, HeContext const &heContext) {
    size_t const xSize = 5, ySize = 5;
    std::array<size_t, 2> dims{ySize, zSize};
    std::vector<helib::Ctxt> oldS(S);
    for (size_t x = 0; x != xSize; ++x) {
        for (size_t y = 0; y != ySize; ++y) {
            for (size_t z = 0; z != zSize; ++z) {
                helib::Ctxt result = heContext.encrypt(1);
                size_t idx = singleIndex<3>({y, (x + 1) % xSize, z}, dims);
                result += oldS[idx];
                idx = singleIndex<3>({y, (x + 2) % xSize, z}, dims);
                result *= oldS[idx];
                idx = singleIndex<3>({y, x, z}, dims);
                S[idx] += result;
            }
        }
    }
}

bit rc(size_t t) {
    size_t const byteMax = 255;
    std::vector<bit> R(CHAR_BIT + t % byteMax, 0);
    R[CHAR_BIT - 1] = 1;
    for (size_t i = 0; i != t % byteMax; ++i) {
        size_t lastIdx = i + CHAR_BIT;
        R[lastIdx] = (R[lastIdx] != R[i]);
        R[lastIdx - 4] = (R[lastIdx - 4] != R[i]);
        R[lastIdx - 5] = (R[lastIdx - 5] != R[i]);
        R[lastIdx - 6] = (R[lastIdx - 6] != R[i]);
    }
    return R.back();
}

void iota(std::vector<helib::Ctxt> &S, size_t zSize, size_t roundIdx) {
    std::array<size_t, 2> dims{5, zSize};
    std::vector<bit> RC(zSize, 0);
    for (size_t i = 0, j = 1; j != zSize; ++i, j *= 2) {
        RC[j - 1] = rc(i + 7 * roundIdx);
    }
    for (size_t z = 0; z != zSize; ++z) {
        size_t idx = singleIndex<3>({0, 0, z}, dims);
        S[idx].addConstant(NTL::ZZX(RC[z]));
    }
}

void keccakP(std::vector<helib::Ctxt> &S, size_t b, size_t n, HeContext const &heContext) {
    size_t zSize = b / 25;
    size_t l = log2(zSize);
    for (size_t i = n; i != 0; --i) {
        size_t roundIdx = 12 + 2 * l - i;
        theta(S, zSize, heContext);
        ro(S, zSize, heContext);
        pi(S, zSize);
        chi(S, zSize, heContext);
        iota(S, zSize, roundIdx);
    }
}

std::vector<helib::Ctxt> pad10_1(size_t x, size_t m, HeContext const &heContext) {
    size_t padSize = x - m % x;
    std::vector<helib::Ctxt> pad(padSize, heContext.encrypt(0));
    pad[0] = pad[padSize - 1] = heContext.encrypt(1);
    return pad;
}

std::vector<helib::Ctxt> sponge(std::function<void(std::vector<helib::Ctxt> &)> f,
                                std::function<std::vector<helib::Ctxt>(size_t, size_t, HeContext const &)> pad,
                                std::vector<helib::Ctxt> const &N, size_t b, size_t r, size_t d, HeContext const &heContext) {
    helib::Ctxt ctxt0 = heContext.encrypt(0);
    std::vector<helib::Ctxt> P(N || pad(r, N.size(), heContext));
    std::vector<helib::Ctxt> S(b, ctxt0);
    for (size_t i = 0; i != P.size(); i += r) {
        size_t j = 0;
        for (; j != r; ++j) {
            S[j] += P[i + j];
        }
        for (; j != b; ++j) {
            S[j] += ctxt0;
        }

        std::cout << "Calling f in sponge..." << std::endl;

        f(S);
    }

    std::cout << "Building Z in sponge..." << std::endl;

    std::vector<helib::Ctxt> Z(std::cbegin(S), std::next(std::cbegin(S), r));
    while (d > Z.size()) {

        std::cout << "Calling f in sponge..." << std::endl;

        f(S);
        Z.insert(std::end(Z), std::cbegin(S), std::next(std::cbegin(S), r));
    }
    Z.resize(d, ctxt0); // call always truncates vector, ctxt0 is provided to avoid compilation error
    return Z;
}

std::vector<helib::Ctxt> hekmac256(std::vector<helib::Ctxt> const &K, std::vector<helib::Ctxt> const &X, std::vector<helib::Ctxt> const &S, size_t L, HeContext const &heContext) {
    static size_t const b = 1600;
    static size_t const rate = 1600 - 512;
    static size_t const bytePadW = 136;
    static size_t const nRounds = 24;
    std::vector<helib::Ctxt> const two0(2, heContext.encrypt(0));
    std::vector<helib::Ctxt> const encodedKmac(encodeString("KMAC", heContext));
    std::function<void(std::vector<helib::Ctxt> &)> const f(std::bind(keccakP, std::placeholders::_1, b, nRounds, heContext));
    std::vector<helib::Ctxt> N(
        bytepad(encodedKmac || encodeString(S, heContext), bytePadW, heContext)
        || bytepad(encodeString(K, heContext), bytePadW, heContext)
        || X
        || encryptBitString(rightEncode(L), heContext)
        || two0
    );

    std::cout << "Calling sponge..." << std::endl;

    return sponge(f, pad10_1, N, b, rate, L, heContext);
}

template <typename T>
void printData(char const *msg, std::vector<T> data) {
    std::cout << msg;
    std::copy(data.cbegin(), data.cend(), std::ostream_iterator<T>(std::cout, " "));
    std::cout << std::endl;
}

void kmacTest(std::vector<uint8_t> const &key, std::vector<uint8_t> const &input, size_t outputLength) {
    std::vector<uint8_t> output(outputLength, 0);
    KMAC256(key.data(), key.size() * CHAR_BIT, input.data(), input.size() * CHAR_BIT, output.data(), output.size() * CHAR_BIT, 0, 0);
    printData("Hash from kmac256: ", output);
}

void hemacTest(std::string const &key, std::string const &input, size_t outputLength) {
    HeContext heContext;
    std::vector<helib::Ctxt> ctxtKey(encryptString(key, heContext));
    std::vector<helib::Ctxt> ctxtInput(encryptString(input, heContext));
    std::vector<helib::Ctxt> ctxtHash(hekmac256(ctxtKey, ctxtInput, std::vector<helib::Ctxt>(), outputLength, heContext));
    std::vector<uint8_t> ptxtHash = decryptString(ctxtHash, heContext);
    printData("Hash from hekmac256: ", ptxtHash);
}

int main() {

    /*
    HeContext heContext;
    auto encoded = encryptBitString(makeBitString("hello world !"), heContext);
    std::copy(
        encoded.cbegin(),
        encoded.cend(),
        std::ostream_iterator<bit>(std::cout," ")
    );
    */
    //std::string heHash = decryptString(, heContext);
    //std::cout << decryptString(encryptString("hello world !", heContext), heContext) << std::endl;

    //std::cout << context.decrypt(context.encrypt(std::string("hello world !"))) << std::endl;
    //std::cout << context.decrypt(context.encrypt(std::string("this is a string..."))) << std::endl;

    std::vector<uint8_t> key{'k', 'e', 'y'};
    std::vector<uint8_t> input{'i', 'n', 'p', 'u', 't'};
    kmacTest(key, input, 10);
    hemacTest("key", "input", 10);
}