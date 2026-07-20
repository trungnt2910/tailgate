#pragma once

#include "tailgate/ByteStream.h"

#include <memory>
#include <string>

namespace tailgate::serve
{

enum class PeerApiIngressStatus
{
    Accepted,
    NotFound,
    Forbidden,
};

struct PeerApiIngressRequest
{
    PeerApiIngressStatus Status = PeerApiIngressStatus::NotFound;
    std::string RequestLine;
    std::string Source;
    std::string Target;
};

class PeerApiIngressHandler final
{
public:
    PeerApiIngressHandler(std::string funnelTarget,
                          std::string certificatePem,
                          std::string privateKeyPem);
    ~PeerApiIngressHandler();

    PeerApiIngressHandler(const PeerApiIngressHandler&) = delete;
    PeerApiIngressHandler& operator=(const PeerApiIngressHandler&) = delete;

    [[nodiscard]] PeerApiIngressRequest ReadRequestAndRespond(IByteStream& peer);
    [[nodiscard]] std::unique_ptr<IByteStream> OpenTlsStream(IByteStream& peer);

private:
    class Impl;
    std::unique_ptr<Impl> Implementation;
};

} // namespace tailgate::serve
