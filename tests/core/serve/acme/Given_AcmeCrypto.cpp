#include <chrono>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/acme/AcmeClient.h>

namespace
{

const std::string Certificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIBsjCCAVmgAwIBAgIUKO0vwx0W1jahJt0MIKkE46NQ9jMwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTbm9kZS5leGFtcGxlLnRzLm5ldDAgFw0yNjA3MjQwODU3Mjla
GA8yMTI2MDYzMDA4NTcyOVowHjEcMBoGA1UEAwwTbm9kZS5leGFtcGxlLnRzLm5l
dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBL/2QDgKhiEvszvx9AIQEEypDJF
xO2m4CiufBXmUS8hZg36egLJZhOYjkB50TsQ0oTud6e/Q1gKF4IDaw51Q8OjczBx
MB0GA1UdDgQWBBShg9R4OBJ0xpkKea4YyVbbMaH9NDAfBgNVHSMEGDAWgBShg9R4
OBJ0xpkKea4YyVbbMaH9NDAPBgNVHRMBAf8EBTADAQH/MB4GA1UdEQQXMBWCE25v
ZGUuZXhhbXBsZS50cy5uZXQwCgYIKoZIzj0EAwIDRwAwRAIgWHgBWHiufNlOgOLb
Y5nKUnYtWPouVdWkSJlQ1P9zNvICIDsTmTK3zwR2ILZe00SxQfd15sa4W5NSp2hp
+86F+uoI
-----END CERTIFICATE-----
)PEM";
constexpr auto MinimumValidity = std::chrono::hours(24);

} // namespace

TEST(Given_FreshProcess, When_CheckingCachedCertificate_Then_ItIsAccepted)
{
    tailgate::acme::MbedTlsCrypto crypto;

    const bool valid = crypto.CertificateValidFor(Certificate, MinimumValidity);

    EXPECT_TRUE(valid);
}
