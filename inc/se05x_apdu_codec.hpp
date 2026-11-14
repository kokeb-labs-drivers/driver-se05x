/**
 * @file se05x_apdu_codec.hpp
 * @brief Every `Codec<C>` specialisation: the one include the command layer needs.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Includes the group headers so that every specialisation is visible before
 * `Device::Execute<>()` instantiates `Codec<C>`.
 */
#ifndef SE05X_APDU_CODEC_HPP
#define SE05X_APDU_CODEC_HPP

#include "se05x_apdu.hpp"
#include "se05x_apdu_crypto.hpp"
#include "se05x_apdu_identity.hpp"
#include "se05x_apdu_misc.hpp"
#include "se05x_apdu_objects.hpp"
#include "se05x_codec.hpp"

#endif // SE05X_APDU_CODEC_HPP
