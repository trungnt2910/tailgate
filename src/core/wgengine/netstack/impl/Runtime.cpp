#include "Runtime.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstring>
#include <mutex>
#include <span>
#include <utility>

#include <lwip/init.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/timeouts.h>

#include <tailgate/wgengine/netstack/Error.h>

#include "TimerWork.h"

namespace tailgate::wgengine::netstack::impl
{

namespace
{

std::once_flag Initialization;
std::uint8_t ExtensionId = LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID;

} // namespace

Runtime::Runtime(std::shared_ptr<base::TimeProvider> timeProvider,
                 std::shared_ptr<crypto::Random> random)
    : m_timeProvider(std::move(timeProvider)),
      m_random(std::move(random)),
      m_services{.Context = this, .Now = Now, .Random = Random, .InitialSequence = InitialSequence}
{
    for (auto& slot : m_pcbs)
    {
        slot.Owner = this;
    }
}

Runtime::~Runtime()
{
    Stop();
}

std::mutex& Runtime::Mutex() noexcept
{
    return m_mutex;
}

void Runtime::Start()
{
    if (m_started)
    {
        return;
    }
    if (!tailgate_lwip_acquire_services(&m_services))
    {
        throw Exception(Error::RuntimeInUse);
    }
    try
    {
        std::call_once(Initialization,
                       []
                       {
                           lwip_init();
                           ExtensionId = tcp_ext_arg_alloc_id();
                       });
        m_extensionId = ExtensionId;
        sys_restart_timeouts();
        m_started = true;
    }
    catch (...)
    {
        tailgate_lwip_release_services(&m_services);
        throw;
    }
}

void Runtime::Stop() noexcept
{
    if (!m_started)
    {
        return;
    }
    ClearConnections();
    m_started = false;
    tailgate_lwip_release_services(&m_services);
}

void Runtime::ClearConnections() noexcept
{
    if (!m_started)
    {
        return;
    }
    // The extension also tracks children still in SYN_RCVD and closed PCBs in
    // TIME_WAIT. Never reset upstream global lists or leave callback contexts behind.
    for (auto& slot : m_pcbs)
    {
        if (slot.Pcb == nullptr)
        {
            continue;
        }
        if (slot.Pcb->state == LISTEN)
        {
            (void)tcp_close(slot.Pcb);
        }
        else
        {
            tcp_abort(slot.Pcb);
        }
    }
    ClearFragments();
}

void Runtime::ClearFragments() noexcept
{
    if (!m_started)
    {
        return;
    }
    // Upstream exposes expiry, not a reset API, for partial IP datagrams. Force
    // bounded expiry while interfaces/providers are alive so fragments from a
    // retired account cannot be assembled with a later session's packets.
    for (unsigned age = 0; age <= IP_REASS_MAXAGE; ++age)
    {
        ip_reass_tmr();
    }
    for (unsigned age = 0; age <= IPV6_REASS_MAXAGE; ++age)
    {
        ip6_reass_tmr();
    }
}

void Runtime::Poll()
{
    if (!m_started)
    {
        throw Exception(Error::NotStarted);
    }
    if (!HasTimerWork())
    {
        // No protocol state aged while asleep. Rebase before accepting new state,
        // including after an idle interval longer than lwIP's 32-bit clock range.
        sys_restart_timeouts();
    }
    sys_check_timeouts();
}

std::optional<base::TimeProvider::TimePoint> Runtime::NextDeadline() const
{
    if (!m_started || !HasTimerWork())
    {
        return std::nullopt;
    }
    const auto delay = sys_timeouts_sleeptime();
    if (delay == SYS_TIMEOUTS_SLEEPTIME_INFINITE)
    {
        return std::nullopt;
    }
    return m_timeProvider->Now() + std::chrono::milliseconds(delay);
}

bool Runtime::Track(tcp_pcb* pcb, void (*destroyed)(void*), void* context) noexcept
{
    static const tcp_ext_arg_callbacks callbacks{.destroy = Destroyed, .passive_open = PassiveOpen};
    if (!m_started || pcb == nullptr)
    {
        return false;
    }
    for (auto& slot : m_pcbs)
    {
        if (slot.Pcb == pcb)
        {
            slot.Destroyed = destroyed;
            slot.Context = context;
            return true;
        }
    }
    for (auto& slot : m_pcbs)
    {
        if (slot.Pcb == nullptr)
        {
            slot.Pcb = pcb;
            slot.Destroyed = destroyed;
            slot.Context = context;
            tcp_ext_arg_set(pcb, m_extensionId, &slot);
            tcp_ext_arg_set_callbacks(pcb, m_extensionId, &callbacks);
            return true;
        }
    }
    return false;
}

void Runtime::Destroyed(std::uint8_t, void* data) noexcept
{
    auto& slot = *static_cast<PcbSlot*>(data);
    slot.Pcb = nullptr;
    if (slot.Destroyed != nullptr)
    {
        slot.Destroyed(slot.Context);
    }
    slot.Destroyed = nullptr;
    slot.Context = nullptr;
    slot.Reservation.reset();
}

err_t Runtime::PassiveOpen(std::uint8_t id, tcp_pcb_listen* listener, tcp_pcb* child) noexcept
{
    auto* slot = static_cast<PcbSlot*>(tcp_ext_arg_get(reinterpret_cast<tcp_pcb*>(listener), id));
    return slot->Owner->Track(child) ? ERR_OK : ERR_MEM;
}

std::size_t Runtime::ConnectionCount() const noexcept
{
    return static_cast<std::size_t>(std::count_if(m_pcbs.begin(),
                                                  m_pcbs.end(),
                                                  [](const PcbSlot& slot)
                                                  {
                                                      return slot.Pcb != nullptr &&
                                                             slot.Pcb->state != LISTEN;
                                                  }));
}

bool Runtime::Started() const noexcept
{
    return m_started;
}

bool Runtime::ReservePort(tcp_pcb* pcb,
                          std::unique_ptr<types::nettype::TcpPortReservation> reservation) noexcept
{
    for (auto& slot : m_pcbs)
    {
        if (slot.Pcb == pcb && pcb != nullptr && !slot.Reservation && reservation)
        {
            slot.Reservation = std::move(reservation);
            return true;
        }
    }
    return false;
}

bool Runtime::OwnsConnection(const ip_addr_t& local,
                             std::uint16_t localPort,
                             const ip_addr_t& remote,
                             std::uint16_t remotePort,
                             std::uint8_t interfaceIndex) const noexcept
{
    for (const auto& slot : m_pcbs)
    {
        const auto* pcb = slot.Pcb;
        if (pcb != nullptr && pcb->state != LISTEN && pcb->netif_idx == interfaceIndex &&
            pcb->local_port == localPort && pcb->remote_port == remotePort &&
            ip_addr_eq(&pcb->local_ip, &local) && ip_addr_eq(&pcb->remote_ip, &remote))
        {
            return true;
        }
    }
    return false;
}

namespace
{

constexpr std::int64_t InitialSequenceTickMicroseconds = 4;
constexpr std::size_t AddressBytes = 16;
constexpr std::size_t TupleBytes = 2 * (1 + AddressBytes + sizeof(std::uint16_t));
// A process-stable secret preserves per-tuple sequence spaces across runtime restarts.
std::once_flag SecretInitialization;
crypto::Bytes32 SequenceSecret{};

void AppendAddress(std::span<std::uint8_t> target, const ip_addr_t& address, std::uint16_t port)
{
    target[0] = IP_GET_TYPE(&address);
    if (IP_IS_V6(&address))
    {
        std::memcpy(target.data() + 1, ip_2_ip6(&address)->addr, AddressBytes);
    }
    else
    {
        std::memcpy(target.data() + 1, &ip_2_ip4(&address)->addr, sizeof(std::uint32_t));
    }
    target[1 + AddressBytes] = static_cast<std::uint8_t>(port >> CHAR_BIT);
    target[2 + AddressBytes] = static_cast<std::uint8_t>(port);
}

} // namespace

std::uint32_t Runtime::Now(void* context)
{
    auto& runtime = *static_cast<Runtime*>(context);
    return static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          runtime.m_timeProvider->Now().time_since_epoch())
                                          .count());
}

std::uint32_t Runtime::Random(void* context)
{
    auto& runtime = *static_cast<Runtime*>(context);
    std::uint32_t value = 0;
    runtime.m_random->Fill(std::span(reinterpret_cast<std::uint8_t*>(&value), sizeof(value)));
    return value;
}

std::uint32_t Runtime::InitialSequence(void* context,
                                       const ip_addr_t* local,
                                       std::uint16_t localPort,
                                       const ip_addr_t* remote,
                                       std::uint16_t remotePort)
{
    auto& runtime = *static_cast<Runtime*>(context);
    std::call_once(SecretInitialization,
                   [&runtime]
                   {
                       runtime.m_random->Fill(SequenceSecret);
                   });
    std::array<std::uint8_t, TupleBytes> tuple{};
    AppendAddress(std::span(tuple).first(TupleBytes / 2), *local, localPort);
    AppendAddress(std::span(tuple).last(TupleBytes / 2), *remote, remotePort);
    const auto hash = crypto::HmacBlake2s256(
        SequenceSecret.data(), SequenceSecret.size(), tuple.data(), tuple.size());
    std::uint32_t keyedOffset = 0;
    std::memcpy(&keyedOffset, hash.data(), sizeof(keyedOffset));
    // RFC 6528 section 3: a secret keyed tuple offset plus the four-microsecond clock.
    const auto ticks = std::chrono::duration_cast<std::chrono::microseconds>(
                           runtime.m_timeProvider->Now().time_since_epoch())
                           .count() /
                       InitialSequenceTickMicroseconds;
    return keyedOffset + static_cast<std::uint32_t>(ticks);
}

} // namespace tailgate::wgengine::netstack::impl
