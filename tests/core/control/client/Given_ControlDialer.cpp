#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/control/ControlDialer.h>

namespace
{

class FakeStream final : public tailgate::IByteStream
{
public:
    explicit FakeStream(std::string name) : Name(std::move(name))
    {
    }

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t*,
                                                          std::size_t size) override
    {
        return size;
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t) override
    {
        return std::vector<std::uint8_t>{};
    }

    std::string Name;
};

} // namespace

TEST(Given_WorkingPlaintextControl, When_Dialing_Then_TlsIsNeverAttempted)
{
    bool tlsDialed = false;
    std::vector<std::string> established;
    const auto plaintext = []()
    {
        return std::make_unique<FakeStream>("plaintext");
    };
    const auto tls = [&]()
    {
        tlsDialed = true;
        return std::make_unique<FakeStream>("tls");
    };
    const auto establish = [&](FakeStream& stream)
    {
        established.push_back(stream.Name);
    };

    const auto outcome = tailgate::control::DialControlStream(plaintext, tls, establish);

    EXPECT_FALSE(outcome.UsedTls);
    EXPECT_FALSE(tlsDialed);
    EXPECT_EQ(established, std::vector<std::string>{"plaintext"});
    EXPECT_EQ(outcome.Stream->Name, "plaintext");
}

TEST(Given_PlaintextControlConnectFailure, When_Dialing_Then_TlsFallbackIsUsed)
{
    std::vector<std::string> established;
    const auto plaintext = []() -> std::unique_ptr<FakeStream>
    {
        throw std::runtime_error("plaintext port is blocked");
    };
    const auto tls = []()
    {
        return std::make_unique<FakeStream>("tls");
    };
    const auto establish = [&](FakeStream& stream)
    {
        established.push_back(stream.Name);
    };

    const auto outcome = tailgate::control::DialControlStream(plaintext, tls, establish);

    EXPECT_TRUE(outcome.UsedTls);
    EXPECT_EQ(established, std::vector<std::string>{"tls"});
    EXPECT_EQ(outcome.Stream->Name, "tls");
}

TEST(Given_PlaintextControlHandshakeFailure, When_Dialing_Then_TlsFallbackIsUsed)
{
    std::vector<std::string> established;
    const auto plaintext = []()
    {
        return std::make_unique<FakeStream>("plaintext");
    };
    const auto tls = []()
    {
        return std::make_unique<FakeStream>("tls");
    };
    const auto establish = [&](FakeStream& stream)
    {
        established.push_back(stream.Name);
        if (stream.Name == "plaintext")
        {
            throw std::runtime_error("upgrade was tampered with");
        }
    };

    const auto outcome = tailgate::control::DialControlStream(plaintext, tls, establish);

    EXPECT_TRUE(outcome.UsedTls);
    EXPECT_EQ(established, (std::vector<std::string>{"plaintext", "tls"}));
    EXPECT_EQ(outcome.Stream->Name, "tls");
}

TEST(Given_BothControlPathsFailing, When_Dialing_Then_TheTlsErrorPropagates)
{
    const auto plaintext = []() -> std::unique_ptr<FakeStream>
    {
        throw std::runtime_error("plaintext port is blocked");
    };
    const auto tls = []() -> std::unique_ptr<FakeStream>
    {
        throw std::runtime_error("TLS port is blocked");
    };
    const auto establish = [](FakeStream&)
    {
    };
    const auto dial = [&]()
    {
        (void)tailgate::control::DialControlStream(plaintext, tls, establish);
    };

    EXPECT_THROW(dial(), std::runtime_error);
}
