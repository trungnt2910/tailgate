#include <cstdlib>
#include <filesystem>
#include <format>
#include <string>
#include <thread>

#include <unistd.h>

#include <gtest/gtest.h>

#include "LinuxPingIpc.h"
#include "LinuxState.h"

TEST(Given_LongPingFields, When_UsingDaemonIpc_Then_StringsRoundTripWithoutTruncation)
{
    const std::filesystem::path home =
        std::filesystem::temp_directory_path() / std::format("tailgate-linux-ping-{}", getpid());
    ASSERT_EQ(setenv("HOME", home.c_str(), 1), 0);
    std::filesystem::create_directories(tailgate::linux_frontend::StateDirectory());
    tailgate::linux_frontend::UniqueFd server = tailgate::linux_frontend::OpenPingServer();
    const std::string target = std::string(1024, 'a') + ".example.ts.net";
    const std::string nodeName = std::string(1024, 'b') + ".example.ts.net";
    tailgate::linux_frontend::PingRequest receivedRequest;
    bool received = false;
    std::thread worker(
        [&]()
        {
            sockaddr_un client{};
            socklen_t clientLength = sizeof(client);
            received = tailgate::linux_frontend::ReceivePingRequest(
                server.Fd, receivedRequest, client, clientLength);
            tailgate::linux_frontend::PingResponse response;
            response.Responded = true;
            response.LatencyMilliseconds = 12;
            response.NodeName = nodeName;
            response.NodeAddress = "100.64.0.1";
            response.Endpoint = "192.0.2.1:12345";
            response.Relay = "DERP(example)";
            response.PeerApiPort = 444;
            tailgate::linux_frontend::SendPingResponse(server.Fd, client, clientLength, response);
        });

    const tailgate::platform::PingResult result =
        tailgate::linux_frontend::RequestDaemonPing(target, 1, true);
    worker.join();
    std::filesystem::remove_all(home);

    EXPECT_TRUE(received);
    EXPECT_EQ(receivedRequest.Target, target);
    EXPECT_EQ(receivedRequest.TimeoutSeconds, 1);
    EXPECT_TRUE(receivedRequest.Tsmp);
    EXPECT_TRUE(result.Responded);
    EXPECT_EQ(result.NodeName, nodeName);
    EXPECT_EQ(result.NodeAddress, "100.64.0.1");
    EXPECT_EQ(result.Endpoint, "192.0.2.1:12345");
    EXPECT_EQ(result.Relay, "DERP(example)");
    EXPECT_EQ(result.LatencyMilliseconds, 12);
    EXPECT_EQ(result.PeerApiPort, 444);
}
