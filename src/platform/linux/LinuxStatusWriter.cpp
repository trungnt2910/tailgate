#include "LinuxStatusWriter.h"

#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>

#include <tailgate/base/Logging.h>

namespace tailgate::linux_frontend
{

struct LinuxStatusWriter::State
{
    std::mutex Mutex;
    std::condition_variable Changed;
    std::optional<DaemonStatus> Pending;
    bool Stopping = false;
};

LinuxStatusWriter::LinuxStatusWriter() : m_state(std::make_shared<State>())
{
    std::shared_ptr<State> state = m_state;
    std::thread(
        [state]()
        {
            while (true)
            {
                std::optional<DaemonStatus> pending;
                {
                    std::unique_lock<std::mutex> lock(state->Mutex);
                    state->Changed.wait(lock,
                                        [&]()
                                        {
                                            return state->Stopping || state->Pending.has_value();
                                        });
                    if (state->Stopping && !state->Pending)
                    {
                        return;
                    }
                    pending = std::move(state->Pending);
                    state->Pending.reset();
                }
                try
                {
                    WriteDaemonStatus(*pending);
                }
                catch (const std::exception& error)
                {
                    tailgate::base::Log(tailgate::base::LogLevel::Error,
                                        "status",
                                        "failed to persist daemon status: " +
                                            std::string(error.what()));
                }
            }
        })
        .detach();
}

LinuxStatusWriter::~LinuxStatusWriter()
{
    {
        std::lock_guard<std::mutex> lock(m_state->Mutex);
        m_state->Stopping = true;
    }
    m_state->Changed.notify_one();
}

void LinuxStatusWriter::Submit(const DaemonStatus& status)
{
    {
        std::lock_guard<std::mutex> lock(m_state->Mutex);
        m_state->Pending = status;
    }
    m_state->Changed.notify_one();
}

} // namespace tailgate::linux_frontend
