#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/Logger.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/drive/driveimpl/compositedav/XmlRewriter.h>
#include <tailgate/net/http/Message.h>
#include <tailgate/wgengine/netstack/Stack.h>

#include "dirfs/FileSystem.h"

#include "Catalog.h"
#include "PeerTransport.h"

namespace tailgate::drive::driveimpl
{

class Exchange final
{
public:
    Exchange(PeerTransport& transport,
             net::http::MessageParserFactory& parsers,
             compositedav::XmlRewriterFactory& xml,
             dirfs::FileSystem& directories,
             base::TimeProvider& time,
             std::shared_ptr<const Catalog> catalog,
             std::unique_ptr<wgengine::netstack::Stream> client);
    ~Exchange();
    [[nodiscard]] bool Poll();
    [[nodiscard]] bool Finished() const noexcept;
    [[nodiscard]] bool Allowed(const Catalog& catalog) const;
    void SetCatalog(std::shared_ptr<const Catalog> catalog);
    [[nodiscard]] base::TimeProvider::TimePoint Deadline() const noexcept;

private:
    base::Logger m_logger{"drive-exchange"};

    struct Leg
    {
        std::unique_ptr<wgengine::netstack::Stream> Stream;
        std::unique_ptr<net::http::MessageParser> Parser;
        std::vector<std::uint8_t> Input;
        std::string Output;
        std::size_t OutputOffset = 0;
        bool Eof = false;
    };

    [[nodiscard]] bool Flush(Leg& leg);
    [[nodiscard]] bool Read(Leg& leg);
    [[nodiscard]] bool ParseRequest();
    [[nodiscard]] bool ParseResponse();
    [[nodiscard]] bool FinishClient();
    void ResetRequest();
    void ReleasePeer();
    void RouteRequest();
    void StartRemote(const Remote& remote);
    void StartResponse();
    void LocalResponse(unsigned status,
                       std::string body = {},
                       std::vector<net::http::HeaderField> fields = {});
    void FinishLocalRequest();
    [[nodiscard]] bool ReadLocalResponse();
    void Fail(unsigned status);

    static constexpr std::size_t ReadSize = 16U * 1024U;
    static constexpr std::size_t MaximumInputBytes = 48U * 1024U;
    static constexpr std::size_t MaximumLocalBody = 64U * 1024U;
    static constexpr auto IdleTimeout = std::chrono::seconds(60);
    static constexpr auto CloseTimeout = std::chrono::seconds(5);

    PeerTransport& m_transport;
    net::http::MessageParserFactory& m_parsers;
    compositedav::XmlRewriterFactory& m_xml;
    dirfs::FileSystem& m_directories;
    base::TimeProvider& m_time;
    std::shared_ptr<const Catalog> m_catalog;
    Leg m_client;
    Leg m_peer;
    std::optional<Remote> m_remote;
    compositedav::PathMapping m_mapping;
    std::unique_ptr<compositedav::XmlRewriter> m_rewriter;
    std::unique_ptr<dirfs::CollectionReader> m_localCollections;
    std::string m_localBody;
    base::TimeProvider::TimePoint m_deadline;
    bool m_routed = false;
    bool m_requestFinished = false;
    bool m_requestChunked = false;
    bool m_responseHeader = false;
    bool m_responseFinished = false;
    bool m_responseChunked = false;
    bool m_finSent = false;
    bool m_finished = false;
    bool m_closeClient = true;
    bool m_reusePeer = false;
    bool m_requestStarted = false;
    unsigned m_informationalResponses = 0;
};

class ExchangeFactory final
{
public:
    ExchangeFactory(PeerTransport& transport,
                    net::http::MessageParserFactory& parsers,
                    compositedav::XmlRewriterFactory& xml,
                    dirfs::FileSystem& directories,
                    base::TimeProvider& time) noexcept;
    [[nodiscard]] std::unique_ptr<Exchange>
    Create(std::shared_ptr<const Catalog> catalog,
           std::unique_ptr<wgengine::netstack::Stream> client);

private:
    PeerTransport& m_transport;
    net::http::MessageParserFactory& m_parsers;
    compositedav::XmlRewriterFactory& m_xml;
    dirfs::FileSystem& m_directories;
    base::TimeProvider& m_time;
};

} // namespace tailgate::drive::driveimpl
