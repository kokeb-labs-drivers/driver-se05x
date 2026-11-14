/**
 * @file se05x_pki.hpp
 * @brief The optional PKI layer in one include: DER, X.509 parsing and chain verification, PKCS#10
 * requests and certificate storage on the chip.
 * @copyright Copyright (c) 2026 The driver-se05x authors. SPDX-License-Identifier: MIT
 *
 * @details
 * Opt-in: `se05x.hpp` does not include it. `docs/pki.md` says what the
 * layer does and does not do (no CA, no revocation, no TLS).
 */
#ifndef SE05X_PKI_HPP
#define SE05X_PKI_HPP

#include "se05x_pki_csr.hpp"    // IWYU pragma: export
#include "se05x_pki_der.hpp"    // IWYU pragma: export
#include "se05x_pki_device.hpp" // IWYU pragma: export
#include "se05x_pki_types.hpp"  // IWYU pragma: export
#include "se05x_pki_verify.hpp" // IWYU pragma: export
#include "se05x_pki_x509.hpp"   // IWYU pragma: export

#endif // SE05X_PKI_HPP
