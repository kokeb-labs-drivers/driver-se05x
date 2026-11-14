/**
 * @file se05x.hpp
 * @brief Umbrella header: the whole public surface of the driver.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * `se05x_kconfig.hpp` is not included: it is the optional ESP-IDF layer. `se05x_irreversible.hpp`
 * is included, but its members exist only when `SE05X_ENABLE_IRREVERSIBLE` is 1.
 */
#ifndef SE05X_HPP
#define SE05X_HPP

#include "se05x_apdu.hpp"
#include "se05x_apdu_codec.hpp"
#include "se05x_apdu_crypto.hpp"
#include "se05x_apdu_identity.hpp"
#include "se05x_apdu_misc.hpp"
#include "se05x_apdu_objects.hpp"
#include "se05x_atr.hpp"
#include "se05x_attest.hpp"
#include "se05x_caps.hpp"
#include "se05x_codec.hpp"
#include "se05x_commands.hpp"
#include "se05x_confirm.hpp"
#include "se05x_crypto.hpp"
#include "se05x_device.hpp"
#include "se05x_device_types.hpp"
#include "se05x_eckey.hpp"
#include "se05x_gate.hpp"
#include "se05x_gp.hpp"
#include "se05x_hrot.hpp"
#include "se05x_ids.hpp"
#include "se05x_irreversible.hpp"
#include "se05x_lifecycle.hpp"
#include "se05x_objects.hpp"
#include "se05x_perso.hpp"
#include "se05x_policy.hpp"
#include "se05x_policy_types.hpp"
#include "se05x_ports.hpp"
#include "se05x_scp03.hpp"
#include "se05x_secret.hpp"
#include "se05x_status.hpp"
#include "se05x_t1.hpp"
#include "se05x_t1_crc.hpp"
#include "se05x_types.hpp"
#include "se05x_wire.hpp"

namespace se05x::detail {
/// The single-shot raw access and the no-I/O accessors of the last reply exist on `Device`
/// (handbook KB-CPP-129: `ReadRaw`, `GetLastStatusWord`).
template <typename P>
concept DeviceHasRawAccess =
    requires(Device<P>& device, ByteSpan command, MutableByteSpan response) {
      device.ReadRaw(command, response);
      device.GetLastStatusWord();
      device.GetLastDetail();
    };
} // namespace se05x::detail

#endif // SE05X_HPP
