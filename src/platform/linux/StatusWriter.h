#pragma once

#include <memory>

#include "State.h"

namespace tailgate::linux_frontend
{

class StatusWriter
{
public:
    StatusWriter();
    ~StatusWriter();
    StatusWriter(const StatusWriter&) = delete;
    StatusWriter& operator=(const StatusWriter&) = delete;

    void Submit(const DaemonStatus& status);

private:
    struct State;
    std::shared_ptr<State> m_state;
};

} // namespace tailgate::linux_frontend
