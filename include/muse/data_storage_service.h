#ifndef MUSE_DATA_STORAGE_SERVICE_H
#define MUSE_DATA_STORAGE_SERVICE_H

#include <memory>
#include <unordered_map>

#include "muse/privacy_service.h"
#include "muse/search_key_ctxt.h"
#include "he_aes_cmac/cmac_keys_ctxt.h"
#include "pre/pre_scheme.h"
#include "pre/public_key.h"
#include "pre/reencryption_key.h"
#include "pre/primary_ctxt.h"

namespace muse {
    class DataStorageService {

        struct Document {
            size_t _authId;
            pre::PrimaryCtxt _ctxt;

            Document(size_t authId, pre::PrimaryCtxt const &ctxt);
        };

        HeAesCmac::CmacKeysCtxt const _hashKey;
        pre::PreScheme _preScheme;
        PrivacyService const &_ps;
        std::unordered_multimap<std::string, Document> _storage;
        std::unordered_map<size_t, std::unordered_map<size_t, pre::ReencryptionKey>> _reKeyTable;

        public:
            DataStorageService(size_t preK1, size_t preK2, size_t preKp,
                               CryptoPP::RandomNumberGenerator &rng, PrivacyService const &ps);
            DataStorageService(size_t preK1, size_t preK2, size_t preKp,
                               std::vector<CryptoPP::byte> const &hashKey, PrivacyService const &ps);

            pre::PreScheme &preScheme();
            HeAesCmac::PublicKey const &hePk() const;

            void grantAccess(size_t fromId, size_t toId, pre::ReencryptionKey const &reKey);
            void revokeAccess(size_t fromId, size_t toId);

            void store(size_t clientId,
                       std::vector<SearchKeyCtxt> const &searchKeys,
                       pre::PrimaryCtxt const &ctxt);
            std::vector<std::unique_ptr<pre::Ctxt>> search(size_t clientId,
                                                           SearchKeyCtxt const &searchKey);

        private:
            void computeHash(SearchKeyCtxt const &input, std::string &output) const;
    };
}

#endif /* !MUSE_DATA_STORAGE_SERVICE_H */