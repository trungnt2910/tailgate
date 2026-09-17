#pragma once

#include <exception>

namespace tailgate::wgengine::netstack
{

enum class Error
{
    RuntimeInUse,
    NotStarted,
    CapacityExceeded,
    InvalidAddress,
    ConnectionFailed,
};

class Exception final : public std::exception
{
public:
    explicit Exception(Error error) noexcept;
    [[nodiscard]] Error Reason() const noexcept;
    [[nodiscard]] const char* what() const noexcept override;

private:
    Error m_error;
};

} // namespace tailgate::wgengine::netstack
