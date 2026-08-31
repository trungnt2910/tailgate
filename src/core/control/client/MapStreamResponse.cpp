#include "MapStreamResponse.h"

#include <format>
#include <string_view>

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
    if (mapSize > maximumSize)
    {
        throw std::runtime_error("Streaming network map exceeds the protocol limit.");
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
