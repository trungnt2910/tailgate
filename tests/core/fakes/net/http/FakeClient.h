#pragma once

#include <deque>
#include <stdexcept>
#include <vector>

#include <tailgate/net/http/Client.h>

namespace tailgate::tests::fakes::net::http
{

class FakeClient final : public tailgate::net::http::Client
{
public:
    tailgate::net::http::Response Send(const tailgate::net::http::Request& request) override
    {
        Requests.push_back(request);
        if (Responses.empty())
        {
            throw std::runtime_error("unexpected HTTP request");
        }
        auto response = Responses.front();
        Responses.pop_front();
        return response;
    }

    std::deque<tailgate::net::http::Response> Responses;
    std::vector<tailgate::net::http::Request> Requests;
};

} // namespace tailgate::tests::fakes::net::http
