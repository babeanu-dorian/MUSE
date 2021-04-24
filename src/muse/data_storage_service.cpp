#include "muse/data_storage_service.h"

#include "pre/reencrypted_ctxt.h"

namespace muse {

    DataStorageService::Document::Document(size_t authId, pre::PrimaryCtxt const &ctxt):
        _authId(authId),
        _ctxt(ctxt)
    {}

    DataStorageService::DataStorageService(size_t preK1,
                                           size_t preK2, size_t preKp,
                                           CryptoPP::RandomNumberGenerator &rng,
                                           PrivacyService const &ps):
        _hashKey(HeAesCmac::CmacKeysCtxt::genKeysCtxt(rng, ps.hePk())),
        _preScheme(preK1, preK2, preKp),
        _ps(ps)
    {}

    DataStorageService::DataStorageService(size_t preK1,
                                           size_t preK2, size_t preKp,
                                           std::vector<CryptoPP::byte> const &hashKey,
                                           PrivacyService const &ps):
        _hashKey(HeAesCmac::CmacKeysCtxt::genKeysCtxt(hashKey, ps.hePk())),
        _preScheme(preK1, preK2, preKp),
        _ps(ps)
    {}

    pre::PreScheme &DataStorageService::preScheme() {
        return _preScheme;
    }

    HeAesCmac::PublicKey const &DataStorageService::hePk() const {
        return _ps.hePk();
    }

    void DataStorageService::grantAccess(size_t fromId, size_t toId, pre::ReencryptionKey const &reKey) {
        _reKeyTable[fromId].emplace(toId, reKey);
    }

    void DataStorageService::revokeAccess(size_t fromId, size_t toId) {
        _reKeyTable[fromId].erase(toId);
    }

    void DataStorageService::store(size_t clientId,
                                   std::vector<SearchKeyCtxt> const &searchKeys,
                                   pre::PrimaryCtxt const &ctxt) {
        Document document(clientId, ctxt);
        for (auto key : searchKeys) {
            std::string hash;
            computeHash(key, hash);
            _storage.emplace(hash, document);
        }
    }

    std::vector<std::unique_ptr<pre::Ctxt>>
        DataStorageService::search(size_t clientId, SearchKeyCtxt const &searchKey) {
        std::string hash;
        std::vector<std::unique_ptr<pre::Ctxt>> result;
        computeHash(searchKey, hash);
        auto range(_storage.equal_range(hash));
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second._authId == clientId) {
                result.emplace_back(new pre::PrimaryCtxt(it->second._ctxt));
            } else {
                auto reKeyIt(_reKeyTable[it->second._authId].find(clientId));
                if (reKeyIt != _reKeyTable[it->second._authId].end()) {
                    result.emplace_back(
                        new pre::ReencryptedCtxt(
                            _preScheme.reencrypt(it->second._ctxt, reKeyIt->second)
                        )
                    );
                }
            }
        }
        return result;
    }

    void DataStorageService::computeHash(SearchKeyCtxt const &input,
                                         std::string &output) const {
        helib::Ctxt hashCtxt(_ps.hePk().pk());
        _ps.hePk().heAesCmac(_hashKey, input.ctxt(), input.isPadded(), hashCtxt);
        _ps.computeHash(hashCtxt, output);
    }
}