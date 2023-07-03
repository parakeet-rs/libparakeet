#pragma once

namespace parakeet_crypto::utils
{

template <typename T> class Defer
{
  private:
    T callback_;

  public:
    Defer(const Defer &) = delete;
    Defer(Defer &&) = delete;
    Defer &operator=(const Defer &) = delete;
    Defer &operator=(Defer &&) = delete;

    Defer(T callback) : callback_(callback)
    {
    }

    ~Defer()
    {
        callback_();
    }
};

} // namespace parakeet_crypto::utils
