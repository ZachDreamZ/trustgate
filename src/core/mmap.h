#pragma once

// Read-only memory-mapped file (Windows + POSIX).
// map() returns false on any failure and falls back to plain reads;
// empty files map as valid zero-length views.

#include <cstddef>
#include <string>

namespace tg {

class MappedFile {
public:
    MappedFile();
    ~MappedFile();
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    bool map(const std::string& path);
    void unmap();

    const void* data() const { return data_; }
    std::size_t size() const { return size_; }
    bool ok() const { return mapped_; }

private:
    const void* data_ = nullptr;
    std::size_t size_ = 0;
    bool mapped_ = false;
#if defined(_WIN32)
    void* fileHandle_ = nullptr;
    void* mapHandle_ = nullptr;
#else
    int fd_ = -1;
#endif
};

}  // namespace tg
