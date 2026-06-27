#include "tailgate/protocol/TlsStream.h"

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <algorithm>
#include <stdexcept>

namespace tailgate::protocol
{
namespace
{

std::runtime_error TlsError(const std::string& operation, int error)
{
    char message[256]{};
    mbedtls_strerror(error, message, sizeof(message));
    return std::runtime_error(operation + ": " + message);
}

} // namespace

class TlsStream::Impl
{
public:
    Impl(IByteStream& transport,
         const std::string& hostname,
         const std::vector<std::uint8_t>& caPem)
        : Transport(transport)
    {
        mbedtls_ssl_init(&Ssl);
        mbedtls_ssl_config_init(&Config);
        mbedtls_x509_crt_init(&Certificates);
        psa_status_t psaResult = psa_crypto_init();
        if (psaResult != PSA_SUCCESS)
        {
            throw std::runtime_error("PSA Crypto initialization failed: " +
                                     std::to_string(psaResult));
        }
        std::vector<std::uint8_t> terminatedCa = caPem;
        if (terminatedCa.empty() || terminatedCa.back() != 0)
        {
            terminatedCa.push_back(0);
        }
        int result =
            mbedtls_x509_crt_parse(&Certificates, terminatedCa.data(), terminatedCa.size());
        if (result < 0)
        {
            throw TlsError("TLS CA parsing failed", result);
        }
        result = mbedtls_ssl_config_defaults(&Config,
                                             MBEDTLS_SSL_IS_CLIENT,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT);
        if (result != 0)
        {
            throw TlsError("TLS configuration failed", result);
        }
        mbedtls_ssl_conf_authmode(&Config, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&Config, &Certificates, nullptr);
        mbedtls_ssl_conf_max_tls_version(&Config, MBEDTLS_SSL_VERSION_TLS1_2);
        result = mbedtls_ssl_setup(&Ssl, &Config);
        if (result != 0)
        {
            throw TlsError("TLS setup failed", result);
        }
        result = mbedtls_ssl_set_hostname(&Ssl, hostname.c_str());
        if (result != 0)
        {
            throw TlsError("TLS hostname setup failed", result);
        }
        mbedtls_ssl_set_bio(&Ssl, this, Send, Receive, nullptr);
        do
        {
            result = mbedtls_ssl_handshake(&Ssl);
        } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);
        if (result != 0)
        {
            throw TlsError("TLS handshake failed", result);
        }
        if (mbedtls_ssl_get_verify_result(&Ssl) != 0)
        {
            throw std::runtime_error("TLS certificate verification failed");
        }
    }

    ~Impl()
    {
        mbedtls_ssl_close_notify(&Ssl);
        mbedtls_ssl_free(&Ssl);
        mbedtls_ssl_config_free(&Config);
        mbedtls_x509_crt_free(&Certificates);
    }

    static int Send(void* context, const unsigned char* data, std::size_t size)
    {
        auto& self = *static_cast<Impl*>(context);
        try
        {
            const std::optional<std::size_t> written = self.Transport.TryWriteSome(data, size);
            return written ? static_cast<int>(*written) : MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        catch (...)
        {
            return MBEDTLS_ERR_NET_SEND_FAILED;
        }
    }

    static int Receive(void* context, unsigned char* data, std::size_t size)
    {
        auto& self = *static_cast<Impl*>(context);
        try
        {
            std::vector<std::uint8_t> received = self.Transport.ReadSome(size);
            if (received.empty())
            {
                return MBEDTLS_ERR_SSL_CONN_EOF;
            }
            std::copy(received.begin(), received.end(), data);
            return static_cast<int>(received.size());
        }
        catch (const StreamWouldBlock&)
        {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        catch (...)
        {
            return MBEDTLS_ERR_NET_RECV_FAILED;
        }
    }

    IByteStream& Transport;
    mbedtls_ssl_context Ssl{};
    mbedtls_ssl_config Config{};
    mbedtls_x509_crt Certificates{};
};

TlsStream::TlsStream(IByteStream& transport,
                     const std::string& hostname,
                     const std::vector<std::uint8_t>& caPem)
    : Implementation(std::make_unique<Impl>(transport, hostname, caPem))
{
}

TlsStream::~TlsStream() = default;

std::optional<std::size_t> TlsStream::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    const int result = mbedtls_ssl_write(&Implementation->Ssl, data, size);
    if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        return std::nullopt;
    }
    if (result < 0)
    {
        throw TlsError("TLS write failed", result);
    }
    return static_cast<std::size_t>(result);
}

std::optional<std::vector<std::uint8_t>> TlsStream::TryReadSome(std::size_t maxBytes)
{
    std::vector<std::uint8_t> data(maxBytes);
    const int result = mbedtls_ssl_read(&Implementation->Ssl, data.data(), data.size());
    if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        return std::nullopt;
    }
    if (result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    {
        return std::vector<std::uint8_t>{};
    }
    if (result < 0)
    {
        throw TlsError("TLS read failed", result);
    }
    data.resize(static_cast<std::size_t>(result));
    return data;
}

bool TlsStream::HasBufferedInput() const
{
    return mbedtls_ssl_check_pending(&Implementation->Ssl) != 0;
}

} // namespace tailgate::protocol
