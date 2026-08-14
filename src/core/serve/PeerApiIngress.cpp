#include <tailgate/serve/PeerApiIngress.h>

#include <cstring>
#include <format>
#include <map>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <tailgate/serve/FunnelConfig.h>

#include "crypto/PsaCryptoContext.h"

namespace tailgate::serve
{

using tailgate::base::IByteStream;

namespace
{

constexpr std::size_t MaximumHeaderBytes = 64U * 1024U;
constexpr int TlsIoWantRead = MBEDTLS_ERR_SSL_WANT_READ;
constexpr int TlsIoWantWrite = MBEDTLS_ERR_SSL_WANT_WRITE;

std::runtime_error TlsError(const std::string& operation, int error)
{
    std::vector<char> message(256);
    mbedtls_strerror(error, message.data(), message.size());
    return std::runtime_error(std::format("{}: {}.", operation, message.data()));
}

std::vector<std::uint8_t> Bytes(std::string_view text)
{
    return {text.begin(), text.end()};
}

std::string Lower(std::string value)
{
    boost::algorithm::to_lower(value);
    return value;
}

std::string Trim(std::string value)
{
    return boost::algorithm::trim_copy(std::move(value));
}

bool ParseHeaders(const std::string& request,
                  std::string& method,
                  std::string& path,
                  std::map<std::string, std::string>& headers)
{
    std::size_t lineEnd = request.find("\r\n");
    if (lineEnd == std::string::npos)
    {
        return false;
    }
    const std::string requestLine = request.substr(0, lineEnd);
    const std::size_t firstSpace = requestLine.find(' ');
    const std::size_t secondSpace =
        firstSpace == std::string::npos ? std::string::npos : requestLine.find(' ', firstSpace + 1);
    if (firstSpace == std::string::npos || secondSpace == std::string::npos)
    {
        return false;
    }
    method = requestLine.substr(0, firstSpace);
    path = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    std::size_t offset = lineEnd + 2;
    while (offset < request.size())
    {
        lineEnd = request.find("\r\n", offset);
        if (lineEnd == std::string::npos || lineEnd == offset)
        {
            return true;
        }
        const std::string line = request.substr(offset, lineEnd - offset);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos)
        {
            headers[Lower(line.substr(0, colon))] = Trim(line.substr(colon + 1));
        }
        offset = lineEnd + 2;
    }
    return true;
}

std::string ReadHeaderBlock(IByteStream& stream)
{
    std::string request;
    while (request.find("\r\n\r\n") == std::string::npos)
    {
        std::vector<std::uint8_t> part = stream.ReadSome(1024);
        if (part.empty())
        {
            break;
        }
        request.append(reinterpret_cast<const char*>(part.data()), part.size());
        if (request.size() > MaximumHeaderBytes)
        {
            break;
        }
    }
    return request;
}

std::string RequestLine(const std::string& request)
{
    const std::size_t lineEnd = request.find("\r\n");
    return request.substr(0, lineEnd == std::string::npos ? request.size() : lineEnd);
}

class TlsIdentity
{
public:
    TlsIdentity(const std::string& certificatePem, const std::string& privateKeyPem)
    {
        if (certificatePem.empty() || privateKeyPem.empty())
        {
            throw std::runtime_error("Funnel TLS certificate or private key is empty.");
        }
        mbedtls_pk_init(&m_key);
        mbedtls_x509_crt_init(&m_certificate);
        mbedtls_ssl_config_init(&m_config);
        int result =
            mbedtls_x509_crt_parse(&m_certificate,
                                   reinterpret_cast<const unsigned char*>(certificatePem.c_str()),
                                   certificatePem.size() + 1U);
        if (result != 0)
        {
            throw TlsError("TLS certificate parse failed", result);
        }
        result = mbedtls_pk_parse_key(&m_key,
                                      reinterpret_cast<const unsigned char*>(privateKeyPem.c_str()),
                                      privateKeyPem.size() + 1U,
                                      nullptr,
                                      0);
        if (result != 0)
        {
            throw TlsError("TLS private key parse failed", result);
        }
        result = mbedtls_ssl_config_defaults(&m_config,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT);
        if (result != 0)
        {
            throw TlsError("TLS server configuration failed", result);
        }
        result = mbedtls_ssl_conf_own_cert(&m_config, &m_certificate, &m_key);
        if (result != 0)
        {
            throw TlsError("TLS own certificate setup failed", result);
        }
        mbedtls_ssl_conf_authmode(&m_config, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_min_tls_version(&m_config, MBEDTLS_SSL_VERSION_TLS1_2);
    }

    ~TlsIdentity()
    {
        mbedtls_ssl_config_free(&m_config);
        mbedtls_x509_crt_free(&m_certificate);
        mbedtls_pk_free(&m_key);
    }

    [[nodiscard]] mbedtls_ssl_config* Config()
    {
        return &m_config;
    }

private:
    tailgate::crypto::detail::PsaCryptoContext m_cryptoContext;
    mbedtls_pk_context m_key{};
    mbedtls_x509_crt m_certificate{};
    mbedtls_ssl_config m_config{};
};

struct TlsStreamContext
{
    IByteStream* Stream = nullptr;
};

int TlsSend(void* context, const unsigned char* data, std::size_t size)
{
    try
    {
        auto& stream = *static_cast<TlsStreamContext*>(context)->Stream;
        const std::optional<std::size_t> written = stream.TryWriteSome(data, size);
        return written ? static_cast<int>(*written) : MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    catch (...)
    {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
}

int TlsReceive(void* context, unsigned char* data, std::size_t size)
{
    try
    {
        auto& stream = *static_cast<TlsStreamContext*>(context)->Stream;
        std::optional<std::vector<std::uint8_t>> received = stream.TryReadSome(size);
        if (!received)
        {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        if (received->empty())
        {
            return MBEDTLS_ERR_SSL_CONN_EOF;
        }
        std::copy(received->begin(), received->end(), data);
        return static_cast<int>(received->size());
    }
    catch (...)
    {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
}

} // namespace

class IngressTlsStream final : public IByteStream
{
public:
    IngressTlsStream(IByteStream& peer, mbedtls_ssl_config* config) : m_context{&peer}
    {
        mbedtls_ssl_init(&m_tls);
        int result = mbedtls_ssl_setup(&m_tls, config);
        if (result != 0)
        {
            throw TlsError("TLS ingress setup failed", result);
        }
        mbedtls_ssl_set_bio(&m_tls, &m_context, TlsSend, TlsReceive, nullptr);
        do
        {
            result = mbedtls_ssl_handshake(&m_tls);
        } while (result == TlsIoWantRead || result == TlsIoWantWrite);
        if (result != 0)
        {
            throw TlsError("TLS ingress handshake failed", result);
        }
    }

    ~IngressTlsStream() override
    {
        (void)mbedtls_ssl_close_notify(&m_tls);
        mbedtls_ssl_free(&m_tls);
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        const int result = mbedtls_ssl_write(&m_tls, data, size);
        if (result == TlsIoWantRead || result == TlsIoWantWrite)
        {
            return std::nullopt;
        }
        if (result < 0)
        {
            throw TlsError("TLS ingress write failed", result);
        }
        return static_cast<std::size_t>(result);
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maxBytes) override
    {
        std::vector<std::uint8_t> buffer(maxBytes);
        const int result = mbedtls_ssl_read(&m_tls, buffer.data(), buffer.size());
        if (result == TlsIoWantRead || result == TlsIoWantWrite)
        {
            return std::nullopt;
        }
        if (result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
            result == MBEDTLS_ERR_SSL_CONN_EOF)
        {
            return std::vector<std::uint8_t>{};
        }
        if (result < 0)
        {
            throw TlsError("TLS ingress read failed", result);
        }
        buffer.resize(static_cast<std::size_t>(result));
        return buffer;
    }

    bool HasBufferedInput() const override
    {
        return mbedtls_ssl_get_bytes_avail(&m_tls) != 0;
    }

private:
    TlsStreamContext m_context;
    mbedtls_ssl_context m_tls{};
};

class PeerApiIngressHandler::Impl
{
public:
    Impl(std::string funnelTarget, std::string certificatePem, std::string privateKeyPem)
        : FunnelTarget(std::move(funnelTarget)),
          CertificatePem(std::move(certificatePem)),
          PrivateKeyPem(std::move(privateKeyPem))
    {
    }

    PeerApiIngressRequest ReadRequestAndRespond(IByteStream& peer)
    {
        const std::string requestText = ReadHeaderBlock(peer);
        PeerApiIngressRequest request;
        request.RequestLine = RequestLine(requestText);

        std::string method;
        std::string path;
        std::map<std::string, std::string> headers;
        if (!ParseHeaders(requestText, method, path, headers) || method != "POST" ||
            path != "/v0/ingress")
        {
            request.Status = PeerApiIngressStatus::NotFound;
            peer.WriteAll(Bytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"));
            return request;
        }

        const auto target = headers.find("tailscale-ingress-target");
        const auto source = headers.find("tailscale-ingress-src");
        if (target != headers.end())
        {
            request.Target = target->second;
        }
        if (source != headers.end())
        {
            request.Source = source->second;
        }
        if (target == headers.end() || source == headers.end() || target->second != FunnelTarget)
        {
            request.Status = PeerApiIngressStatus::Forbidden;
            peer.WriteAll(Bytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"));
            return request;
        }

        request.Status = PeerApiIngressStatus::Accepted;
        peer.WriteAll(Bytes("HTTP/1.1 101 Switching Protocols\r\n\r\n"));
        return request;
    }

    std::unique_ptr<IByteStream> OpenTlsStream(IByteStream& peer)
    {
        std::lock_guard lock(IdentityMutex);
        if (!Identity)
        {
            Identity = std::make_unique<TlsIdentity>(CertificatePem, PrivateKeyPem);
        }
        return std::make_unique<IngressTlsStream>(peer, Identity->Config());
    }

    std::string FunnelTarget;
    std::string CertificatePem;
    std::string PrivateKeyPem;
    std::mutex IdentityMutex;
    std::unique_ptr<TlsIdentity> Identity;
};

PeerApiIngressHandler::PeerApiIngressHandler(std::string funnelTarget,
                                             std::string certificatePem,
                                             std::string privateKeyPem)
    : Implementation(std::make_unique<Impl>(
          std::move(funnelTarget), std::move(certificatePem), std::move(privateKeyPem)))
{
}

PeerApiIngressHandler::~PeerApiIngressHandler() = default;

PeerApiIngressRequest PeerApiIngressHandler::ReadRequestAndRespond(IByteStream& peer)
{
    return Implementation->ReadRequestAndRespond(peer);
}

std::unique_ptr<IByteStream> PeerApiIngressHandler::OpenTlsStream(IByteStream& peer)
{
    return Implementation->OpenTlsStream(peer);
}

} // namespace tailgate::serve
