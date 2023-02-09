#include "IStream.h"

#include <fstream>

namespace parakeet_crypto
{

class InputFileStream final : public IReadSeekable
{
  private:
    std::ifstream &ifs_;

  public:
    InputFileStream(std::ifstream &ifs) : ifs_(ifs)
    {
    }

    size_t Read(uint8_t *buffer, size_t len) override
    {
        ifs_.read(reinterpret_cast<char *>(buffer), static_cast<std::streamsize>(len)); // NOLINT(*-reinterpret-cast)
        return ifs_.gcount();
    }
    void Seek(size_t position, SeekDirection seek_dir) override
    {
        ifs_.seekg(static_cast<std::streamsize>(position),
                   seek_dir == SeekDirection::CURRENT_POSITION ? std::ifstream::cur
                   : seek_dir == SeekDirection::FILE_BEGIN     ? std::ifstream::beg
                                                               : std::ifstream::end);
    }
    size_t GetSize() override
    {
        auto pos = ifs_.tellg();
        ifs_.seekg(0, std::ifstream::end);
        auto size = ifs_.tellg();
        ifs_.seekg(pos, std::ifstream::beg);
        return size;
    }
    size_t GetOffset() override
    {
        return ifs_.tellg();
    }
};

class OutputFileStream final : public IWriteable
{
  private:
    std::ofstream &ofs_;

  public:
    OutputFileStream(std::ofstream &ofs) : ofs_(ofs)
    {
    }

    void Write(const uint8_t *buffer, size_t len) override
    {
        ofs_.write(reinterpret_cast<const char *>(buffer), // NOLINT(*-reinterpret-cast)
                   static_cast<std::streamsize>(len));
    }
};

class InputMemoryStream final : public IReadSeekable
{
  public:
    std::vector<uint8_t> &GetData()
    {
        return data_;
    }

  private:
    std::vector<uint8_t> data_;
    size_t offset_{0};

  public:
    InputMemoryStream() = default;
    InputMemoryStream(std::vector<uint8_t> &data) : data_(data)
    {
    }

    size_t Read(uint8_t *buffer, size_t len) override
    {
        auto actual_read = std::min(len, data_.size() - offset_);
        std::copy_n(&data_.at(offset_), actual_read, buffer);
        offset_ += actual_read;
        return actual_read;
    }
    void Seek(size_t position, SeekDirection seek_dir) override
    {
        size_t next_offset{0};
        switch (seek_dir)
        {
        case SeekDirection::FILE_BEGIN:
            next_offset = position;
            break;
        case SeekDirection::CURRENT_POSITION:
            next_offset = offset_ + position;
            break;
        case SeekDirection::FILE_END_BACKWARDS:
            next_offset = data_.size() - position;
            break;
        default:
            return;
        }

        offset_ = std::max(std::min(next_offset, data_.size()), size_t{0});
    }
    size_t GetSize() override
    {
        return data_.size();
    }
    size_t GetOffset() override
    {
        return offset_;
    }
};

class OutputMemoryStream final : public IWriteable
{
  public:
    std::vector<uint8_t> &GetData()
    {
        return data_;
    }

  private:
    std::vector<uint8_t> data_{};
    size_t offset_{0};

  public:
    OutputMemoryStream() = default;
    OutputMemoryStream(std::vector<uint8_t> &data) : data_(data)
    {
    }

    void Write(const uint8_t *buffer, size_t len) override
    {
        data_.insert(data_.end(), buffer, buffer + len);
    }
};

}; // namespace parakeet_crypto