#include "Exchange.h"

#include <algorithm>
#include <array>
#include <exception>
#include <format>

namespace tailgate::drive::driveimpl
{

Exchange::Exchange(PeerTransport& transport,
                   net::http::MessageParserFactory& parsers,
                   compositedav::XmlRewriterFactory& xml,
                   dirfs::FileSystem& directories,
                   base::TimeProvider& time,
                   std::shared_ptr<const Catalog> catalog,
                   std::unique_ptr<wgengine::netstack::Stream> client)
    : m_transport(transport),
      m_parsers(parsers),
      m_xml(xml),
      m_directories(directories),
      m_time(time),
      m_catalog(std::move(catalog)),
      m_deadline(time.Now() + IdleTimeout)
{
    m_client.Stream = std::move(client);
    m_client.Parser = m_parsers.Create({});
}

Exchange::~Exchange()
{
    if (m_client.Stream)
    {
        m_client.Stream->Abort();
    }
    if (m_peer.Stream)
    {
        m_peer.Stream->Abort();
    }
}

bool Exchange::Finished() const noexcept
{
    return m_finished;
}

base::TimeProvider::TimePoint Exchange::Deadline() const noexcept
{
    return m_deadline;
}

bool Exchange::Allowed(const Catalog& catalog) const
{
    if (catalog.SelfKey != m_catalog->SelfKey || catalog.Domain != m_catalog->Domain ||
        !catalog.Access)
    {
        return false;
    }
    return !m_remote || std::ranges::any_of(catalog.Remotes,
                                            [&](const Remote& remote)
                                            {
                                                return remote == *m_remote;
                                            });
}

void Exchange::SetCatalog(std::shared_ptr<const Catalog> catalog)
{
    m_catalog = std::move(catalog);
}

bool Exchange::Poll()
{
    if (m_finished)
    {
        return false;
    }
    if (m_time.Now() >= m_deadline)
    {
        m_logger.LogDebug("HTTP session deadline reached: upstream_selected={}, "
                          "response_started={}, shutdown_started={}",
                          m_remote.has_value(),
                          m_responseHeader,
                          m_finSent);
        m_finished = true;
        return true;
    }
    bool progress = false;
    try
    {
        progress |= Flush(m_client);
        if (m_peer.Stream)
        {
            progress |= Flush(m_peer);
        }
        if (!m_responseFinished)
        {
            if (m_localCollections && m_client.Output.empty())
            {
                progress |= ReadLocalResponse();
            }
            // Service the response first so an early denial stops further body forwarding.
            if (m_peer.Stream && m_client.Output.empty())
            {
                progress |= Read(m_peer);
                progress |= ParseResponse();
            }
            if (!m_requestFinished && !m_responseHeader && m_peer.Output.empty())
            {
                progress |= Read(m_client);
                progress |= ParseRequest();
            }
        }
        if (m_responseFinished && m_client.Output.empty())
        {
            progress |= FinishClient();
        }
    }
    catch (const std::exception&)
    {
        // A local malformed request is a 400; failures after dialing are upstream failures.
        // Once final headers were queued, no replacement success/error message can be framed.
        Fail(m_remote ? 502 : 400);
        progress = true;
    }
    if (progress && !m_finSent)
    {
        m_deadline = m_time.Now() + IdleTimeout;
    }
    return progress;
}

void Exchange::Fail(unsigned status)
{
    m_logger.LogWarning("HTTP exchange failed: status={}, upstream_selected={}, "
                        "response_started={}",
                        status,
                        m_remote.has_value(),
                        m_responseHeader);
    m_closeClient = true;
    m_reusePeer = false;
    if (m_peer.Stream)
    {
        m_peer.Stream->Abort();
        m_peer.Stream.reset();
    }
    if (m_responseHeader)
    {
        m_finished = true;
        return;
    }
    m_client.Output.clear();
    m_client.OutputOffset = 0;
    LocalResponse(status);
}

ExchangeFactory::ExchangeFactory(PeerTransport& transport,
                                 net::http::MessageParserFactory& parsers,
                                 compositedav::XmlRewriterFactory& xml,
                                 dirfs::FileSystem& directories,
                                 base::TimeProvider& time) noexcept
    : m_transport(transport),
      m_parsers(parsers),
      m_xml(xml),
      m_directories(directories),
      m_time(time)
{
}

std::unique_ptr<Exchange>
ExchangeFactory::Create(std::shared_ptr<const Catalog> catalog,
                        std::unique_ptr<wgengine::netstack::Stream> client)
{
    return std::make_unique<Exchange>(m_transport,
                                      m_parsers,
                                      m_xml,
                                      m_directories,
                                      m_time,
                                      std::move(catalog),
                                      std::move(client));
}

bool Exchange::Flush(Leg& leg)
{
    if (leg.Output.empty() || !leg.Stream ||
        leg.Stream->State() == wgengine::netstack::StreamState::Connecting)
    {
        return false;
    }
    const auto written = leg.Stream->TryWriteSome(
        reinterpret_cast<const std::uint8_t*>(leg.Output.data()) + leg.OutputOffset,
        leg.Output.size() - leg.OutputOffset);
    if (!written)
    {
        return false;
    }
    if (*written == 0)
    {
        throw net::http::MessageError(net::http::MessageErrorKind::Truncated);
    }
    leg.OutputOffset += *written;
    if (leg.OutputOffset == leg.Output.size())
    {
        leg.Output.clear();
        leg.OutputOffset = 0;
    }
    return true;
}

bool Exchange::Read(Leg& leg)
{
    if (leg.Eof || leg.Input.size() >= MaximumInputBytes ||
        leg.Stream->State() == wgengine::netstack::StreamState::Connecting)
    {
        return false;
    }
    const auto input =
        leg.Stream->TryReadSome(std::min(ReadSize, MaximumInputBytes - leg.Input.size()));
    if (!input)
    {
        return false;
    }
    if (input->empty())
    {
        leg.Eof = true;
    }
    else
    {
        leg.Input.insert(leg.Input.end(), input->begin(), input->end());
    }
    return true;
}

bool Exchange::FinishClient()
{
    if (!m_closeClient)
    {
        ResetRequest();
        return true;
    }
    bool progress = false;
    if (!m_finSent)
    {
        if (!m_client.Stream->TryShutdownWrite())
        {
            return false;
        }
        m_finSent = true;
        m_deadline = m_time.Now() + CloseTimeout;
        progress = true;
    }
    // Linger long enough for the client to consume the final response. Closing with unread
    // request bytes would make lwIP send RST and could discard a useful early error response.
    m_client.Input.clear();
    progress |= Read(m_client);
    m_client.Input.clear();
    if (m_client.Eof && m_client.Stream->TryClose())
    {
        m_finished = true;
        progress = true;
    }
    return progress;
}

namespace http = net::http;

void Exchange::LocalResponse(unsigned status,
                             std::string body,
                             std::vector<http::HeaderField> fields)
{
    http::MessageHead response;
    response.Kind(http::MessageKind::Response);
    response.Status(status);
    m_closeClient |= !m_client.Parser->Complete();
    if (m_client.Parser->HeaderComplete())
    {
        response.Version(m_client.Parser->Head().Version());
    }
    response.Fields(std::move(fields));
    response.AddField({"Content-Length", std::format("{}", body.size())});
    if (m_closeClient)
    {
        response.AddField({"Connection", "close"});
    }
    m_client.Output += response.Encode() + body;
    m_responseHeader = true;
    m_responseFinished = true;
    m_requestFinished = true;
}

void Exchange::FinishLocalRequest()
{
    auto response = m_directories.Serve(m_client.Parser->Head(), m_localBody, m_catalog);
    std::vector<http::HeaderField> fields;
    for (const auto& [name, value] : response.Metadata.Headers())
    {
        fields.emplace_back(name, value);
    }
    if (!response.Collections)
    {
        LocalResponse(response.Metadata.Status(), response.Metadata.Body(), std::move(fields));
        return;
    }
    m_localCollections = std::move(response.Collections);
    http::MessageHead head;
    head.Kind(http::MessageKind::Response);
    head.Status(response.Metadata.Status());
    head.Version(m_client.Parser->Head().Version());
    head.Fields(std::move(fields));
    m_responseChunked = head.Version() == 11;
    if (m_responseChunked)
    {
        head.AddField({"Transfer-Encoding", "chunked"});
    }
    if (m_closeClient)
    {
        head.AddField({"Connection", "close"});
    }
    m_client.Output += head.Encode();
    m_responseHeader = true;
}

bool Exchange::ReadLocalResponse()
{
    const auto body = m_localCollections->Read(ReadSize);
    if (!body.empty())
    {
        m_client.Output +=
            m_responseChunked
                ? http::ChunkEncoder::Encode(
                      std::span(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()))
                : body;
    }
    if (m_localCollections->Finished())
    {
        if (m_responseChunked)
        {
            m_client.Output += http::ChunkEncoder::EncodeLast({});
        }
        m_responseFinished = true;
        m_localCollections.reset();
    }
    return !body.empty() || m_responseFinished;
}

bool Exchange::ParseRequest()
{
    std::array<std::uint8_t, ReadSize> body{};
    http::ParseProgress progress;
    if (!m_client.Input.empty())
    {
        m_requestStarted = true;
        progress = m_client.Parser->Put(m_client.Input, body);
        m_client.Input.erase(m_client.Input.begin(), m_client.Input.begin() + progress.Consumed);
    }
    else if (m_client.Eof)
    {
        if (!m_requestStarted)
        {
            // Normal EOF between persistent requests is not a malformed HTTP message.
            m_finished = m_client.Stream->TryClose();
            return m_finished;
        }
        m_client.Parser->Finish();
    }
    if (!m_routed && m_client.Parser->HeaderComplete())
    {
        RouteRequest();
    }
    if (m_responseFinished)
    {
        return true;
    }
    if (progress.BodyBytes != 0)
    {
        if (m_peer.Stream)
        {
            if (m_requestChunked)
            {
                m_peer.Output +=
                    http::ChunkEncoder::Encode(std::span(body).first(progress.BodyBytes));
            }
            else
            {
                m_peer.Output.append(reinterpret_cast<const char*>(body.data()),
                                     progress.BodyBytes);
            }
        }
        else
        {
            if (progress.BodyBytes > MaximumLocalBody - m_localBody.size())
            {
                LocalResponse(413);
                return true;
            }
            m_localBody.append(reinterpret_cast<const char*>(body.data()), progress.BodyBytes);
        }
    }
    if (m_client.Parser->Complete())
    {
        const auto trailers = m_client.Parser->Trailers();
        if (m_peer.Stream && !m_requestFinished && m_requestChunked)
        {
            m_peer.Output += http::ChunkEncoder::EncodeLast(trailers);
        }
        else if (!m_peer.Stream)
        {
            FinishLocalRequest();
        }
        m_requestFinished = true;
    }
    if (progress.Consumed == 0 && m_client.Input.size() == MaximumInputBytes)
    {
        throw http::MessageError(http::MessageErrorKind::HeaderLimit);
    }
    return progress.Consumed != 0 || m_requestFinished;
}

void Exchange::RouteRequest()
{
    const auto& head = m_client.Parser->Head();
    // A proxy must not persist HTTP/1.0 client connections (RFC 9112 section 9.3).
    m_closeClient = head.Version() != 11 || !m_client.Parser->KeepAlive();
    const auto host = head.SingleField("Host");
    if (!host || !std::ranges::any_of(m_catalog->LocalAuthorities,
                                      [&](const auto& allowed)
                                      {
                                          return http::HeaderField::EqualText(*host, allowed);
                                      }))
    {
        LocalResponse(403);
        return;
    }
    if (const auto origin = head.SingleField("Origin");
        origin && !http::HeaderField::EqualText(*origin, "http://" + std::string(*host)))
    {
        LocalResponse(403);
        return;
    }
    if (!m_catalog->Access)
    {
        LocalResponse(403);
        return;
    }
    const auto path = compositedav::Path::Parse(head.Target());
    if (!path.Segments().empty() && path.Segments()[0] != m_catalog->Domain)
    {
        LocalResponse(404);
        return;
    }
    m_routed = true;
    const Remote* remote = nullptr;
    if (path.Segments().size() >= 2)
    {
        const auto found = std::ranges::find_if(m_catalog->Remotes,
                                                [&](const auto& candidate)
                                                {
                                                    return candidate.Name == path.Segments()[1];
                                                });
        if (found == m_catalog->Remotes.end())
        {
            LocalResponse(404);
            return;
        }
        remote = &*found;
    }
    const bool depthSensitive = head.Method() == "PROPFIND" || head.Method() == "LOCK";
    const auto depth = depthSensitive ? head.SingleField("Depth") : std::nullopt;
    const bool peerDirectory = path.Segments().size() == 2 && depthSensitive &&
                               (!depth || (*depth != "1" && *depth != "infinity"));
    if (path.Segments().size() < 2 || peerDirectory)
    {
        if (const auto expect = head.SingleField("Expect"); expect)
        {
            if (!http::HeaderField::EqualText(*expect, "100-continue"))
            {
                LocalResponse(417);
            }
            else if (!m_client.Parser->Complete())
            {
                http::MessageHead interim;
                interim.Kind(http::MessageKind::Response);
                interim.Status(100);
                m_client.Output += interim.Encode();
            }
        }
        return;
    }
    StartRemote(*remote);
}

void Exchange::StartRemote(const Remote& remote)
{
    const auto& request = m_client.Parser->Head();
    const wgengine::netstack::TcpEndpoint endpoint{
        .Address = remote.Ipv4 ? *remote.Ipv4 : *remote.Ipv6,
        .Port = remote.Ipv4 ? remote.PeerApi4Port : remote.PeerApi6Port};
    m_mapping.Domain = m_catalog->Domain;
    m_mapping.RemoteName = remote.Name;
    m_mapping.LocalAuthorities = m_catalog->LocalAuthorities;
    m_mapping.PeerAuthority =
        endpoint.Address.Family() == net::AddressFamily::Ipv4
            ? std::format("{}:{}", endpoint.Address.ToString(), endpoint.Port)
            : std::format("[{}]:{}", endpoint.Address.ToString(), endpoint.Port);
    auto outgoing = request;
    outgoing.Version(11);
    outgoing.Target(m_mapping.ToPeerRequest(request.Target()));
    const auto destination = request.SingleField("Destination");
    if ((request.Method() == "MOVE" || request.Method() == "COPY") && !destination)
    {
        LocalResponse(400);
        return;
    }
    outgoing.RemoveHopByHopFields();
    if (request.Method() == "PROPFIND" || request.Method() == "PROPPATCH" ||
        request.Method() == "LOCK")
    {
        outgoing.RemoveField("Accept-Encoding");
        outgoing.AddField(http::HeaderField{"Accept-Encoding", "identity"});
    }
    auto fields = outgoing.Fields();
    for (auto& field : fields)
    {
        if (http::HeaderField::EqualText(field.Name(), "Destination"))
        {
            field.Value(m_mapping.ToPeerResource(field.Value()));
        }
        if (http::HeaderField::EqualText(field.Name(), "If"))
        {
            field.Value(m_mapping.RewriteIf(field.Value()));
        }
    }
    outgoing.Fields(std::move(fields));
    (void)request.SingleField("If");
    for (const auto name : {"Host", "Content-Length", "Authorization", "Cookie", "Origin"})
    {
        outgoing.RemoveField(name);
    }
    outgoing.AddField(http::HeaderField{"Host", m_mapping.PeerAuthority});
    m_requestFinished = m_client.Parser->Complete();
    const auto length = request.SingleField("Content-Length");
    m_requestChunked = !m_requestFinished && !length;
    // Preserve known lengths: exporters can distinguish a fixed-length request body from
    // an unknown-length one (notably when rejecting unsupported MKCOL bodies).
    outgoing.AddField(m_requestChunked
                          ? http::HeaderField{"Transfer-Encoding", "chunked"}
                          : http::HeaderField{"Content-Length", std::string(length.value_or("0"))});
    m_peer.Output = outgoing.Encode();
    m_remote = remote;
    m_peer.Stream = m_transport.Acquire(remote);
    m_peer.Parser = m_parsers.Create(http::ParserOptions{.Kind = http::MessageKind::Response,
                                                         .SkipBody = request.Method() == "HEAD"});
}

bool Exchange::ParseResponse()
{
    std::array<std::uint8_t, ReadSize> body{};
    http::ParseProgress progress;
    if (!m_peer.Input.empty())
    {
        progress = m_peer.Parser->Put(m_peer.Input, body);
        m_peer.Input.erase(m_peer.Input.begin(), m_peer.Input.begin() + progress.Consumed);
    }
    else if (m_peer.Eof)
    {
        m_peer.Parser->Finish();
    }
    if (!m_responseHeader && m_peer.Parser->HeaderComplete())
    {
        const auto status = m_peer.Parser->Head().Status();
        if (status < 200)
        {
            constexpr unsigned MaximumInformationalResponses = 16;
            if (status == 101 || ++m_informationalResponses > MaximumInformationalResponses)
            {
                throw http::MessageError(http::MessageErrorKind::Malformed);
            }
            auto interim = m_peer.Parser->Head();
            interim.RemoveHopByHopFields();
            m_client.Output += interim.Encode();
            m_peer.Parser = m_parsers.Create(
                http::ParserOptions{.Kind = http::MessageKind::Response,
                                    .SkipBody = m_client.Parser->Head().Method() == "HEAD"});
            return true;
        }
        StartResponse();
    }
    if (progress.BodyBytes != 0 || (m_rewriter && m_peer.Parser->Complete()))
    {
        const auto bytes = std::span(body).first(progress.BodyBytes);
        const auto output =
            m_rewriter ? m_rewriter->Transform(bytes, m_peer.Parser->Complete())
                       : std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        m_client.Output +=
            m_responseChunked
                ? http::ChunkEncoder::Encode(std::span(
                      reinterpret_cast<const std::uint8_t*>(output.data()), output.size()))
                : output;
    }
    if (m_peer.Parser->Complete())
    {
        auto trailers = m_peer.Parser->Trailers();
        if (m_rewriter)
        {
            // Integrity trailers describe the original representation, not rewritten XML.
            http::MessageHead trailerFields;
            trailerFields.Fields(std::move(trailers));
            for (const auto name : {"Content-MD5", "Digest", "Content-Digest", "Repr-Digest"})
            {
                trailerFields.RemoveField(name);
            }
            trailers = std::move(trailerFields.Fields());
        }
        if (m_responseChunked)
        {
            m_client.Output += http::ChunkEncoder::EncodeLast(trailers);
        }
        m_responseFinished = true;
        ReleasePeer();
    }
    if (progress.Consumed == 0 && m_peer.Input.size() == MaximumInputBytes)
    {
        throw http::MessageError(http::MessageErrorKind::HeaderLimit);
    }
    return progress.Consumed != 0 || m_responseFinished;
}

void Exchange::StartResponse()
{
    auto head = m_peer.Parser->Head();
    const auto& request = m_client.Parser->Head();
    const bool uploadComplete = m_client.Parser->Complete() && m_peer.Output.empty();
    m_reusePeer = uploadComplete && m_peer.Parser->KeepAlive();
    m_closeClient |= !uploadComplete;
    const bool bodyAllowed =
        request.Method() != "HEAD" && head.Status() != 204 && head.Status() != 304;
    const auto type = head.SingleField("Content-Type");
    const auto mediaType = type ? type->substr(0, type->find_first_of("; \t")) : std::string_view{};
    const bool xmlType = http::HeaderField::EqualText(mediaType, "application/xml") ||
                         http::HeaderField::EqualText(mediaType, "text/xml");
    const bool metadata = request.Method() == "PROPFIND" || request.Method() == "PROPPATCH" ||
                          request.Method() == "LOCK";
    if (bodyAllowed && metadata && !m_peer.Parser->Complete() &&
        ((head.Status() >= 200 && head.Status() < 300) || xmlType))
    {
        if (const auto encoding = head.SingleField("Content-Encoding");
            encoding && !http::HeaderField::EqualText(*encoding, "identity"))
        {
            throw http::MessageError(http::MessageErrorKind::Malformed);
        }
        m_rewriter = m_xml.Create(m_mapping);
        head.RemoveField("Content-Type");
        head.AddField(http::HeaderField{"Content-Type", "application/xml; charset=utf-8"});
        for (const auto name : {"ETag", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest"})
        {
            head.RemoveField(name);
        }
    }
    head.RemoveHopByHopFields();
    auto fields = head.Fields();
    for (auto& field : fields)
    {
        if (http::HeaderField::EqualText(field.Name(), "Location") ||
            http::HeaderField::EqualText(field.Name(), "Content-Location"))
        {
            field.Value(m_mapping.ToLocalResource(field.Value()));
        }
    }
    head.Fields(std::move(fields));
    head.Version(request.Version());
    m_responseChunked = bodyAllowed && request.Version() == 11;
    if (bodyAllowed || head.Status() == 204)
    {
        head.RemoveField("Content-Length");
    }
    if (m_responseChunked)
    {
        head.AddField(http::HeaderField{"Transfer-Encoding", "chunked"});
    }
    if (m_closeClient)
    {
        head.AddField(http::HeaderField{"Connection", "close"});
    }
    m_client.Output += head.Encode();
    m_responseHeader = true;
    if (!uploadComplete)
    {
        m_requestFinished = true;
        m_peer.Output.clear();
        m_peer.OutputOffset = 0;
        (void)m_peer.Stream->TryShutdownWrite();
    }
}

void Exchange::ReleasePeer()
{
    if (m_reusePeer && !m_peer.Eof && m_peer.Input.empty())
    {
        m_transport.Release(*m_remote, std::move(m_peer.Stream));
    }
    else
    {
        // Never reuse close-delimited responses, early upload rejections, or a stream
        // containing unsolicited bytes after the final response.
        if (!m_peer.Stream->TryClose())
        {
            m_peer.Stream->Abort();
        }
        m_peer.Stream.reset();
    }
}

void Exchange::ResetRequest()
{
    // Preserve unread client bytes: pipelined requests are served strictly in order,
    // only after the preceding response has completely left our bounded output buffer.
    m_client.Parser = m_parsers.Create({});
    m_peer = Leg{};
    m_remote.reset();
    m_mapping = compositedav::PathMapping{};
    m_rewriter.reset();
    m_localCollections.reset();
    m_localBody.clear();
    m_routed = false;
    m_requestFinished = false;
    m_requestChunked = false;
    m_responseHeader = false;
    m_responseFinished = false;
    m_responseChunked = false;
    m_closeClient = true;
    m_reusePeer = false;
    m_requestStarted = false;
    m_informationalResponses = 0;
}

} // namespace tailgate::drive::driveimpl
