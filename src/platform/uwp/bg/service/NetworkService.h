#pragma once

#include <exception>

#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>

#include "manager/DataPlaneManager.h"
#include "manager/SessionManager.h"
#include "service/ServiceBase.h"

#include "tstun/PacketDevice.h"

namespace tailgate::uwp::bg::service
{

class PingService;

enum class NetworkServiceErrorCode
{
    PacketDeviceAlreadyOpen,
    PacketQueueFull,
    PacketDeviceClosed,
};

class NetworkServiceError final : public std::exception
{
public:
    explicit NetworkServiceError(NetworkServiceErrorCode code) noexcept : m_code(code)
    {
    }

    [[nodiscard]] NetworkServiceErrorCode Code() const noexcept
    {
        return m_code;
    }

    [[nodiscard]] const char* what() const noexcept override;

private:
    NetworkServiceErrorCode m_code;
};

class NetworkService final : public ServiceBase
{
public:
    NetworkService(manager::DataPlaneManager& dataPlaneManager,
                   manager::SessionManager& sessionManager,
                   PingService& pingService,
                   tailgate::hosted::Client& client,
                   tailgate::hosted::ClientSession& hostedSession,
                   PacketDevice& packetDevice);

    void Start(SessionGeneration generation) override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(EncapsulationContext& context) override;
    void Decapsulate(DecapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;

private:
    void DrainDevice(std::vector<std::vector<std::uint8_t>>& localOutput);

    tailgate::hosted::Client& m_client;
    tailgate::hosted::ClientSession& m_hostedSession;
    PacketDevice& m_packetDevice;
    PingService& m_pingService;
    manager::SessionManager& m_sessionManager;
};

} // namespace tailgate::uwp::bg::service
