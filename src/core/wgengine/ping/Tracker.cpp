#include "tailgate/wgengine/ping/Tracker.h"

namespace tailgate::wgengine::ping
{

DiscoProbe DiscoProbe::Build(disco::Disco& owner, const crypto::Bytes32& discoKey)
{
    const auto transaction = owner.NewTransactionId();
    return DiscoProbe{.Transaction = transaction,
                      .Payload = owner.BuildPing(discoKey, transaction)};
}

Tracker::~Tracker() = default;

} // namespace tailgate::wgengine::ping
