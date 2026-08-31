#pragma once

#include <map>
#include <stdexcept>
#include <string>
#include <utility>

namespace tailgate::net::http
{

class Request final
{
public:
    Request(std::string method,
            std::string url,
            std::map<std::string, std::string> headers,
            std::string body)
        : m_method(std::move(method)),
          m_url(std::move(url)),
          m_headers(std::move(headers)),
          m_body(std::move(body))
    {
    }

    [[nodiscard]] std::string Encode() const;

    [[nodiscard]] const std::string& Method() const noexcept
    {
        return m_method;
    }

    [[nodiscard]] const std::string& Url() const noexcept
    {
        return m_url;
    }

    [[nodiscard]] const std::map<std::string, std::string>& Headers() const noexcept
    {
        return m_headers;
    }

    [[nodiscard]] const std::string& Body() const noexcept
    {
        return m_body;
    }

private:
    std::string m_method;
    std::string m_url;
    std::map<std::string, std::string> m_headers;
    std::string m_body;
};

class Response final
{
public:
    Response(int status, std::map<std::string, std::string> headers, std::string body)
        : m_status(status), m_headers(std::move(headers)), m_body(std::move(body))
    {
    }

    [[nodiscard]] static Response Decode(const std::string& encoded);

    [[nodiscard]] int Status() const noexcept
    {
        return m_status;
    }

    [[nodiscard]] const std::map<std::string, std::string>& Headers() const noexcept
    {
        return m_headers;
    }

    [[nodiscard]] const std::string& Body() const noexcept
    {
        return m_body;
    }

private:
    int m_status;
    std::map<std::string, std::string> m_headers;
    std::string m_body;
};

class HttpsUrl final
{
public:
    [[nodiscard]] static HttpsUrl Parse(const std::string& url);

    [[nodiscard]] const std::string& Host() const noexcept
    {
        return m_host;
    }

    [[nodiscard]] const std::string& Service() const noexcept
    {
        return m_service;
    }

    [[nodiscard]] const std::string& Path() const noexcept
    {
        return m_path;
    }

private:
    HttpsUrl(std::string host, std::string service, std::string path)
        : m_host(std::move(host)), m_service(std::move(service)), m_path(std::move(path))
    {
    }

    std::string m_host;
    std::string m_service;
    std::string m_path;
};

enum class CodecErrorKind
{
    InvalidUrl,
    MissingHeaders,
    InvalidStatusLine,
    InvalidStatusCode,
    InvalidChunkSize,
    TruncatedChunk,
    InvalidChunkDelimiter,
};

class CodecError final : public std::runtime_error
{
public:
    explicit CodecError(CodecErrorKind kind);
    [[nodiscard]] CodecErrorKind Kind() const noexcept;

private:
    CodecErrorKind m_kind;
};

class Client
{
public:
    virtual ~Client();
    [[nodiscard]] virtual Response Send(const Request& request) = 0;

protected:
    Client() = default;
};

} // namespace tailgate::net::http
