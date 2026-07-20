#pragma once

#include "LinuxState.h"

#include <memory>

namespace tailgate::linux_frontend
{

class LinuxStatusWriter
{
public:
    LinuxStatusWriter();
    ~LinuxStatusWriter();
    LinuxStatusWriter(const LinuxStatusWriter&) = delete;
    LinuxStatusWriter& operator=(const LinuxStatusWriter&) = delete;

    void Submit(const DaemonStatus& status);

private:
    struct State;
    std::shared_ptr<State> m_state;
};

} // namespace tailgate::linux_frontend
