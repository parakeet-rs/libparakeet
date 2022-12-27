#pragma once

#include "kugou/KugouFileLoader.h"
#include "kuwo/KuwoFileLoader.h"
#include "netease/NCMFileLoader.h"
#include "tencent/EKeyProvider.h"
#include "tencent/JooxFileLoader.h"
#include "tencent/QMCv1Loader.h"
#include "tencent/QMCv2Loader.h"
#include "xiami/XiamiFileLoader.h"
#include "ximalaya/XimalayaFileLoader.h"

#include "parakeet-crypto/utils/AudioTypes.h"

#include <istream>
#include <optional>
#include <vector>

namespace parakeet_crypto::decryption {

namespace config {

struct KugouConfig {
  kugou::KugouSingleSlotKey slot_key_1 = {};
  kugou::KugouV4FileKeyExpansionTable v4_file_key_expansion_table = {};
  kugou::KugouV4SlotKeyExpansionTable v4_slot_key_expansion_table = {};
};

struct KuwoConfig {
  kuwo::KuwoKey key = {};
};

struct NeteaseConfig {
  netease::NCMContentKeyProtectionKey key = {};
};

struct JooxConfig {
  std::string install_uuid = {};
  tencent::JooxSalt salt = {};
};

struct QMCConfig {
  uint8_t ekey_seed = {};
  tencent::QMCv1Key static_cipher_key = {};
  parakeet_crypto::misc::tencent::QMCEncV2Stage1Key enc_v2_stage1_key = {};
  parakeet_crypto::misc::tencent::QMCEncV2Stage2Key enc_v2_stage2_key = {};
};

/**
 * @brief Decryption parameter for Ximalaya (Android).
 * For X2M / X3M, at least one of the `scramble_table` / `scramble_table_parameter` value needs to be specified
 *   for a successful decryption.
 * When both supplied, the `scramble_table_parameter` take priority.
 */
struct XimalayaConfig {
  ximalaya::X2MContentKey x2m_content_key = {};
  ximalaya::ScrambleTable x2m_scramble_table = {};
  std::optional<ximalaya::XmlyScrambleTableParameter> x2m_scramble_table_parameters = {};

  ximalaya::X3MContentKey x3m_content_key = {};
  ximalaya::ScrambleTable x3m_scramble_table = {};
  std::optional<ximalaya::XmlyScrambleTableParameter> x3m_scramble_table_parameters = {};
};

struct DecryptionConfig {
  KugouConfig kugou = {};
  KuwoConfig kuwo = {};
  NeteaseConfig netease = {};
  JooxConfig joox = {};
  QMCConfig qmc = {};
  XimalayaConfig ximalaya = {};
};

}  // namespace config

struct DetectionResult {
  /**
   * @brief Number of bytes to preserve, i.e. data that should be discarded.
   * This is usually the padding that was used by the detection.
   */
  std::size_t footer_discard_len;
  /**
   * @brief Number of bytes to skip when reading the file.
   */
  std::size_t header_discard_len;
  utils::AudioType audio_type;
  std::string audio_ext;
  std::unique_ptr<DecryptionStream> decryptor;
};

class DecryptionManager {
 public:
  virtual const config::DecryptionConfig& GetConfig() const = 0;
  virtual void SetConfig(config::DecryptionConfig& config) = 0;

  /**
   * Use this method to inject EKeys.
   * @return
   */
  virtual tencent::EKeyProvider& GetEKeyProvider() { return ekey_provider_; }

  /**
   * @brief Get a list of detected decryptor.
   * Header will be supplied to the decryptor;
   *   when decrypting, feed decryptor with rest of the file.
   *
   * @deprecated Use the `std::istream` variant instead.
   * @param header File header
   * @param footer File footer
   * @return std::vector<std::unique_ptr<DetectionResult>>
   */
  virtual std::vector<std::unique_ptr<DetectionResult>> DetectDecryptors(const DetectionBuffer& header,
                                                                         const DetectionBuffer& footer,
                                                                         bool remove_unknown_format = true) = 0;

  /**
   * @brief Get a list of detected decryptor.
   * Header will be supplied to the decryptor;
   *   when decrypting, feed decryptor with rest of the file.
   *
   * @param stream Input stream. For memory stream, use `std::stringstream`.
   *               Ensure stream has at least `kDetectionBufferLen * 3` bytes.
   * @return std::vector<std::unique_ptr<DetectionResult>>
   */
  virtual std::vector<std::unique_ptr<DetectionResult>> DetectDecryptors(std::istream& stream,
                                                                         bool remove_unknown_format = true) = 0;

  /**
   * @brief Get the first working decryptor.
   * Header will be supplied to the decryptor;
   *   when decrypting, feed decryptor with rest of the file.
   * @deprecated Use the `std::istream` variant instead.
   *
   * @param header
   * @param footer
   * @return std::unique_ptr<DetectionResult>
   */
  std::unique_ptr<DetectionResult> DetectDecryptor(const DetectionBuffer& header,
                                                   const DetectionBuffer& footer,
                                                   bool remove_unknown_format = true) {
    auto result = DetectDecryptors(header, footer, remove_unknown_format);
    if (result.size() > 0) {
      return std::move(result[0]);
    }
    return nullptr;
  }

  /**
   * @brief Get the first working decryptor.
   * Header will be supplied to the decryptor;
   *   when decrypting, feed decryptor with rest of the file.
   *
   * @param stream Input stream. For memory stream, use `std::stringstream`.
   *               Ensure stream has at least `kDetectionBufferLen * 3` bytes.
   * @return std::unique_ptr<DetectionResult>
   */
  std::unique_ptr<DetectionResult> DetectDecryptor(std::istream& stream, bool remove_unknown_format = true) {
    auto result = DetectDecryptors(stream, remove_unknown_format);
    if (result.size() > 0) {
      return std::move(result[0]);
    }
    return nullptr;
  }

  static std::unique_ptr<DecryptionManager> Create();

 private:
  tencent::EKeyProvider ekey_provider_;
};

}  // namespace parakeet_crypto::decryption
