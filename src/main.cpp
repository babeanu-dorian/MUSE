#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>
#include <utility>
#include <cmath>

#include "pre/pre_scheme.h"
#include "pre/key_pair.h"
#include "pre/reencryption_key.h"
#include "pre/primary_ctxt.h"
#include "pre/reencrypted_ctxt.h"

#include "cryptopp/hrtimer.h"
#include "cryptopp/nbtheory.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"
#include "cryptopp/cmac.h"
#include "cryptopp/aes.h"

#include "muse/client.h"

struct ExperimentParams {
    std::string _message;
    HeAesCmac::SecurityParams _heSecurityParams;
    size_t _repeatAmount;
    size_t _preSecurityParam;
    size_t _searchKeySize;
    size_t _documentSize;
    size_t _searchKeysPerDocument;
    size_t _totalDocuments;
    bool _sameSearchKeys;
};

ExperimentParams baseSetup() {
    ExperimentParams setup;
    setup._heSecurityParams.m = 65281;
    setup._heSecurityParams.r = 1;
    setup._heSecurityParams.cm = 1;
    setup._heSecurityParams.k = 1600;
    setup._heSecurityParams.c = 3;
    setup._heSecurityParams.hwsk = 64;
    setup._heSecurityParams.mvec = {};
    setup._heSecurityParams.gens = {43073, 22214};
    setup._heSecurityParams.ords = {96, -14};
    setup._repeatAmount = 10;
    setup._preSecurityParam = 1024;
    setup._searchKeySize = 8;       // 8 bytes
    setup._documentSize = 10485760; // 10 MB
    setup._searchKeysPerDocument = 1;
    setup._totalDocuments = 1;
    setup._sameSearchKeys = false;
    return setup;
}

std::string intToStringOfSize(size_t n, size_t size) {
    std::string result(std::to_string(n));
    result.resize(size);
    return result;
}

void runExperiment(ExperimentParams const &params) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ThreadUserTimer timer;
    muse::PrivacyService ps(rng, params._heSecurityParams);
    muse::DataStorageService ds(params._preSecurityParam, params._preSecurityParam,
                                params._preSecurityParam, rng, ps);
    muse::Client client0(0, params._searchKeySize, ds);
    muse::Client client1(1, params._searchKeySize, ds);
    client0.grantAccess(1, client1.prePk());

    std::string content(params._documentSize, UCHAR_MAX);
    CryptoPP::Integer document(content.c_str());

    size_t searchKeyAmount = params._searchKeysPerDocument * params._totalDocuments;

    std::vector<std::string> searchKeys;
    searchKeys.reserve(searchKeyAmount);
    for (size_t i = 0; i != searchKeyAmount; ++i) {
        size_t keyVal = (params._sameSearchKeys ? i % params._searchKeysPerDocument : i);
        searchKeys.push_back(intToStringOfSize(keyVal, params._searchKeySize));
    }

    size_t dId = 0;
    for (auto it = searchKeys.cbegin(); it != searchKeys.cend(); std::advance(it, params._searchKeysPerDocument)) {
        std::vector<std::string> currentSearchKeys(it, std::next(it, params._searchKeysPerDocument));
        timer.StartTimer();
        client0.store(currentSearchKeys, document);
        std::cout << "Stored document " << ++dId << " in "
                  << timer.ElapsedTimeAsDouble()
                  << " seconds." << std::endl;
    }

    timer.StartTimer();
    std::vector<CryptoPP::Integer> resultC0(client0.search(searchKeys.front()));
    std::cout << "Retrieved " << resultC0.size() << " documents for client0 in "
            << timer.ElapsedTimeAsDouble()
            << " seconds." << std::endl;

    timer.StartTimer();
    std::vector<CryptoPP::Integer> resultC1(client1.search(searchKeys.front()));
    std::cout << "Retrieved " << resultC1.size() << " documents for client1 in "
            << timer.ElapsedTimeAsDouble()
            << " seconds." << std::endl;
}

void repeatExperiment(ExperimentParams const &params) {
    std::cout << params._message << std::endl << std::endl;
    for (size_t i = 0; i != params._repeatAmount; ++i) {
        try {
            std::cout << "Try " << i << std::endl;
            runExperiment(params);
            std::cout << std::endl;
        } catch(...) {
            --i;
        }
    }
    std::cout << std::endl;
}

void searchKeySizeExperiment() {
    ExperimentParams experiment(baseSetup());
    size_t base = 8;

    for (size_t i = 1; i != 5; ++i) {
        experiment._searchKeySize = i * base;
        std::string message("Search-key size experiment, size ");
        message.append(std::to_string(experiment._searchKeySize));
        experiment._message = message;
        repeatExperiment(experiment);
    }
}

void documentSizeExperiment() {
    ExperimentParams experiment(baseSetup());
    size_t base = 1073741824;  // 1 GB

    for (size_t i = 1; i != 11; ++i) {
        experiment._documentSize = i * base;
        std::string message("Document size experiment, size ");
        message.append(std::to_string(i));
        message.append(" GB");
        experiment._message = message;
        repeatExperiment(experiment);
    }
}

void searchKeysPerDocumentExperiment() {
    ExperimentParams experiment(baseSetup());
    size_t base = 8;

    for (size_t i = 1; i != 6; ++i) {
        experiment._searchKeysPerDocument = i * base;
        std::string message("Search-keys per document experiment, value ");
        message.append(std::to_string(experiment._searchKeysPerDocument));
        experiment._message = message;
        repeatExperiment(experiment);
    }
}

void totalDocumentsExperiment() {
    ExperimentParams experiment(baseSetup());
    size_t base = 8;

    for (size_t i = 1; i != 6; ++i) {
        experiment._totalDocuments = i * base;
        std::string message("Total documents experiment, value ");
        message.append(std::to_string(experiment._totalDocuments));
        experiment._message = message;
        repeatExperiment(experiment);
    }
}

void documentsPerSearchKeyExperiment() {
    ExperimentParams experiment(baseSetup());
    experiment._sameSearchKeys = true;
    size_t base = 8;

    for (size_t i = 1; i != 6; ++i) {
        experiment._totalDocuments = i * base;
        std::string message("Documents per search-key experiment, value ");
        message.append(std::to_string(experiment._totalDocuments));
        experiment._message = message;
        repeatExperiment(experiment);
    }
}

void viewContextInfo(HeAesCmac::SecurityParams const &params) {
    helib::Context context(HeAesCmac::KeyPair::genContext(params));
    std::cout << "security: " << context.securityLevel() << std::endl;
    std::cout << "slots: " << context.ea->getPAlgebra().getNSlots() << std::endl;
}

int main() {
    viewContextInfo(baseSetup()._heSecurityParams);
    //searchKeySizeExperiment();
    //documentSizeExperiment();
    //searchKeysPerDocumentExperiment();
    //totalDocumentsExperiment();
    //viewContextInfo();
}