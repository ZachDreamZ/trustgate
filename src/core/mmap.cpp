#include "core/mmap.h"

#include <filesystem>

#include "core/fsutil.h"

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace tg {

MappedFile::MappedFile() = default;

MappedFile::~MappedFile() {
    unmap();
}

#if defined(_WIN32)

bool MappedFile::map(const std::string& path) {
    unmap();
    std::wstring w = pathFromUtf8(path).native();
    HANDLE h = CreateFileW(w.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) {
        CloseHandle(h);
        return false;
    }
    if (sz.QuadPart == 0) {
        CloseHandle(h);
        size_ = 0;
        data_ = nullptr;
        mapped_ = true;
        return true;
    }
    HANDLE m = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (m == nullptr) {
        CloseHandle(h);
        return false;
    }
    void* v = MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (v == nullptr) {
        CloseHandle(m);
        CloseHandle(h);
        return false;
    }
    fileHandle_ = h;
    mapHandle_ = m;
    data_ = v;
    size_ = static_cast<std::size_t>(sz.QuadPart);
    mapped_ = true;
    return true;
}

void MappedFile::unmap() {
    if (!mapped_) return;
    if (data_ != nullptr) UnmapViewOfFile(data_);
    if (mapHandle_ != nullptr) CloseHandle(static_cast<HANDLE>(mapHandle_));
    if (fileHandle_ != nullptr) CloseHandle(static_cast<HANDLE>(fileHandle_));
    data_ = nullptr;
    size_ = 0;
    mapped_ = false;
    fileHandle_ = nullptr;
    mapHandle_ = nullptr;
}

#else

bool MappedFile::map(const std::string& path) {
    unmap();
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return false;
    }
    if (st.st_size == 0) {
        close(fd);
        size_ = 0;
        data_ = nullptr;
        mapped_ = true;
        return true;
    }
    void* v = mmap(nullptr, static_cast<std::size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (v == MAP_FAILED) return false;
    data_ = v;
    size_ = static_cast<std::size_t>(st.st_size);
    mapped_ = true;
    fd_ = -1;
    return true;
}

void MappedFile::unmap() {
    if (!mapped_) return;
    if (data_ != nullptr && size_ > 0) munmap(const_cast<void*>(data_), size_);
    if (fd_ >= 0) close(fd_);
    data_ = nullptr;
    size_ = 0;
    mapped_ = false;
    fd_ = -1;
}

#endif

}  // namespace tg
