#include "muse/search_key_ctxt.h"

namespace muse {
    SearchKeyCtxt::SearchKeyCtxt(std::vector<helib::Ctxt> const &ctxt, bool padded):
        _ctxt(ctxt),
        _padded(padded)
    {}

    std::vector<helib::Ctxt> const &SearchKeyCtxt::ctxt() const {
        return _ctxt;
    }
    
    bool SearchKeyCtxt::isPadded() const {
        return _padded;
    }
}