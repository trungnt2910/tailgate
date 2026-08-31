#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <tailgate/control/base/H2.h>

namespace tailgate::control::client
{

class MapStreamRejected final : public std::runtime_error
{
public:
    MapStreamRejected(int status, std::string body);
};

class MapStreamResponse final
{
public:
    void Start(std::uint32_t streamId) noexcept;
    [[nodiscard]] bool Handles(std::uint32_t streamId) const noexcept;
    void ReceiveHeaders(const tailgate::control::base::H2Headers& headers);
    void ReceiveData(const std::vector<std::uint8_t>& data);
    void Finish();
    [[nodiscard]] std::optional<std::string> TakeMap(std::size_t maximumSize);

private:
    std::uint32_t m_streamId = 0;
    std::optional<int> m_status;
    std::vector<std::uint8_t> m_body;
};

} // namespace tailgate::control::client
