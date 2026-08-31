#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/base/ByteStream.h>
#include <tailgate/net/Ipv4Address.h>

namespace tailgate::tests::fakes::net::dns
{

class FakeByteStream final : public tailgate::base::ByteStream
{
public:
    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override
    {
        m_written.insert(m_written.end(), data, data + size);
        if (m_response.empty() && m_written.size() >= DnsLengthSize + DnsHeaderSize)
        {
            BuildResponse();
        }
        return size;
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maximumSize) override
    {
        const std::size_t size = std::min({maximumSize, MaximumReadSize, m_response.size()});
        std::vector<std::uint8_t> result(m_response.begin(),
                                         m_response.begin() + static_cast<std::ptrdiff_t>(size));
        m_response.erase(m_response.begin(),
                         m_response.begin() + static_cast<std::ptrdiff_t>(size));
        return result;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& Written() const noexcept
    {
        return m_written;
    }

private:
    static void Append16(std::vector<std::uint8_t>& output, std::uint16_t value)
    {
        output.push_back(static_cast<std::uint8_t>(value >> 8U));
        output.push_back(static_cast<std::uint8_t>(value));
    }

    static void Append32(std::vector<std::uint8_t>& output, std::uint32_t value)
    {
        output.push_back(static_cast<std::uint8_t>(value >> 24U));
        output.push_back(static_cast<std::uint8_t>(value >> 16U));
        output.push_back(static_cast<std::uint8_t>(value >> 8U));
        output.push_back(static_cast<std::uint8_t>(value));
    }

    void BuildResponse()
    {
        const std::size_t querySize = (static_cast<std::size_t>(m_written[0]) << 8U) | m_written[1];
        if (m_written.size() < DnsLengthSize + querySize)
        {
            return;
        }
        std::vector<std::uint8_t> message(m_written.begin() + DnsLengthSize,
                                          m_written.begin() + DnsLengthSize + querySize);
        message[2] = SuccessfulResponseFlagsHigh;
        message[3] = SuccessfulResponseFlagsLow;
        message[6] = 0;
        message[7] = 1;
        Append16(message, QuestionNamePointer);
        Append16(message, DnsTypeA);
        Append16(message, DnsClassInternet);
        Append32(message, TimeToLiveSeconds);
        Append16(message, Ipv4AddressSize);
        Append32(message, ResponseAddress.HostOrder());
        m_response = {static_cast<std::uint8_t>(message.size() >> 8U),
                      static_cast<std::uint8_t>(message.size())};
        m_response.insert(m_response.end(), message.begin(), message.end());
    }

    static constexpr std::size_t DnsLengthSize = 2;
    static constexpr std::size_t DnsHeaderSize = 12;
    static constexpr std::size_t MaximumReadSize = 3;
    static constexpr std::uint8_t SuccessfulResponseFlagsHigh = 0x81;
    static constexpr std::uint8_t SuccessfulResponseFlagsLow = 0x80;
    static constexpr std::uint16_t QuestionNamePointer = 0xc00c;
    static constexpr std::uint16_t DnsTypeA = 1;
    static constexpr std::uint16_t DnsClassInternet = 1;
    static constexpr std::uint32_t TimeToLiveSeconds = 30;
    static constexpr std::uint16_t Ipv4AddressSize = 4;
    static constexpr tailgate::net::Ipv4Address ResponseAddress =
        tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 40);

    std::vector<std::uint8_t> m_written;
    std::vector<std::uint8_t> m_response;
};

} // namespace tailgate::tests::fakes::net::dns
