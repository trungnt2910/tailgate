#include "LinuxFiles.h"

#include <fstream>
#include <iterator>
#include <stdexcept>

namespace tailgate::linux_frontend
{

std::string ReadTextFile(const std::string& path)
{
    std::ifstream file(path);
    if (!file)
    {
        throw std::runtime_error("failed to open " + path);
    }
    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' '))
    {
        text.pop_back();
    }
    return text;
}

std::vector<std::uint8_t> ReadBinaryFile(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("failed to open " + path);
    }
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

} // namespace tailgate::linux_frontend
