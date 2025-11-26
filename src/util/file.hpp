#pragma once

#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#ifndef _MSC_VER
#include <dirent.h>
#endif

#include <oxenc/common.h>

namespace srouter::util
{
    /// Reads a binary file from disk into a string.  Throws on error.
    std::string file_to_string(
        const std::filesystem::path& filename, size_t max_size = std::numeric_limits<size_t>::max());

    /// Reads a binary file from disk directly into a buffer.  Throws a std::length_error if the
    /// file is bigger than the buffer.  Returns the bytes copied on success.
    size_t file_to_buffer(const std::filesystem::path& filename, char* buffer, size_t buffer_size);

    /// Dumps binary string contents to disk. The file is overwritten if it already exists.  Throws
    /// on error.
    void buffer_to_file(const std::filesystem::path& filename, std::string_view contents);

    /// Extracts the filename as a std::string from a filename from a file.  On most platforms this is
    /// simply the same as path.string(), but that is non-portable (because of Windows) and so this
    /// gives you a version that works everywhere by extracting the utf8 representation (which
    /// converts from native on Windows).
    inline std::string path_as_str(const std::filesystem::path& p)
    {
        auto u8path = p.u8string();
        return {reinterpret_cast<const char*>(u8path.data()), u8path.size()};
    }
    /// Loads a fs::path from a utf8 string by first mashing that string into a std::u8string_view;
    /// this is primarily for portability, where fs::paths are not constructible from std::string on
    /// Windows.
    inline std::filesystem::path utf8_path(std::string_view p)
    {
        return std::filesystem::path{std::u8string_view{reinterpret_cast<const char8_t*>(p.data()), p.size()}};
    }

    struct FileHash
    {
        size_t operator()(const std::filesystem::path& f) const
        {
            std::hash<std::string> h;
            return h(f.string());
        }
    };

    using error_code_t = std::error_code;

    /// Ensure that a file exists and has correct permissions
    /// return any error code or success
    error_code_t EnsurePrivateFile(const std::filesystem::path& pathname);

    /// open a stream to a file and ensure it exists before open
    /// sets any permissions on creation
    template <typename T>
    std::optional<T> OpenFileStream(const std::filesystem::path& pathname, std::ios::openmode mode)
    {
        if (EnsurePrivateFile(pathname))
            return {};
        return std::make_optional<T>(pathname, mode);
    }

}  // namespace srouter::util
