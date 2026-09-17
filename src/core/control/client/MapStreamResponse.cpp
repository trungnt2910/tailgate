#include "MapStreamResponse.h"

#include <format>
#include <string_view>
#include <utility>

#include <tailgate/base/Strings.h>

namespace tailgate::control::client
{
namespace
{

constexpr std::size_t MapLengthSize = 4;

std::string RejectionMessage(int status, std::string_view body)
{
    const std::string_view trimmedBody = tailgate::base::TrimEnd(body);
    if (trimmedBody.empty())
    {
        return std::format("Control streaming map failed with HTTP status {}.", status);
    }
    return std::format(
        "Control streaming map failed with HTTP status {}: {}.", status, trimmedBody);
}

} // namespace

MapStreamRejected::MapStreamRejected(int status, std::string body)
    : std::runtime_error(RejectionMessage(status, body))
{
}

InvalidMapResponse::InvalidMapResponse()
    : std::runtime_error("Control map response has invalid or incomplete length framing.")
{
}

std::string MapStreamResponse::DecodeMap(const std::vector<std::uint8_t>& body,
                                         std::size_t maximumSize)
{
    // Read-only maps have the same length framing as streaming updates. A length byte can
    // itself be '{', so searching for the start of JSON would interpret that prefix as data.
    MapStreamResponse response;
    response.ReceiveData(body);
    auto map = response.TakeMap(maximumSize);
    if (!map || !response.m_body.empty())
    {
        throw InvalidMapResponse();
    }
    return std::move(*map);
}

void MapStreamResponse::Start(std::uint32_t streamId) noexcept
{
    m_streamId = streamId;
    m_status.reset();
    m_body.clear();
}

bool MapStreamResponse::Handles(std::uint32_t streamId) const noexcept
{
    return m_streamId != 0 && streamId == m_streamId;
}

void MapStreamResponse::ReceiveHeaders(const tailgate::control::base::H2Headers& headers)
{
    m_status = tailgate::control::base::H2Codec::Status(headers);
}

void MapStreamResponse::ReceiveData(const std::vector<std::uint8_t>& data)
{
    m_body.insert(m_body.end(), data.begin(), data.end());
}

void MapStreamResponse::Finish()
{
    if (!m_status)
    {
        throw std::runtime_error("Control streaming map ended without an HTTP status.");
    }
    if (*m_status >= 300)
    {
        throw MapStreamRejected(*m_status, std::string(m_body.begin(), m_body.end()));
    }
    throw std::runtime_error("Control streaming map ended unexpectedly.");
}

std::optional<std::string> MapStreamResponse::TakeMap(std::size_t maximumSize)
{
    if (m_body.size() < MapLengthSize)
    {
        return std::nullopt;
    }
    const std::size_t mapSize = m_body[0] | (static_cast<std::size_t>(m_body[1]) << 8U) |
                                (static_cast<std::size_t>(m_body[2]) << 16U) |
                                (static_cast<std::size_t>(m_body[3]) << 24U);
    if (mapSize == 0 || mapSize > maximumSize)
    {
        throw InvalidMapResponse();
    }
    if (m_body.size() < MapLengthSize + mapSize)
    {
        return std::nullopt;
    }
    std::string result(m_body.begin() + static_cast<std::ptrdiff_t>(MapLengthSize),
                       m_body.begin() + static_cast<std::ptrdiff_t>(MapLengthSize + mapSize));
    m_body.erase(m_body.begin(),
                 m_body.begin() + static_cast<std::ptrdiff_t>(MapLengthSize + mapSize));
    return result;
}

} // namespace tailgate::control::client
