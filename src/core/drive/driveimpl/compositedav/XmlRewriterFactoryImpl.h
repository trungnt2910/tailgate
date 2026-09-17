#pragma once

#include <tailgate/crypto/Random.h>
#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>

namespace tailgate::drive::driveimpl::compositedav
{

class XmlRewriterFactoryImpl final : public XmlRewriterFactory
{
public:
    explicit XmlRewriterFactoryImpl(crypto::Random& random) noexcept;
    [[nodiscard]] std::unique_ptr<XmlRewriter> Create(const PathMapping& mapping) override;
    [[nodiscard]] PropfindQuery ParsePropfind(std::span<const std::uint8_t> input) override;
    [[nodiscard]] std::vector<PropertyName>
    ParseProppatch(std::span<const std::uint8_t> input) override;

private:
    crypto::Random& m_random;
};

} // namespace tailgate::drive::driveimpl::compositedav
