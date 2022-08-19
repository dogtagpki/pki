//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.security.Principal;
import java.util.Optional;

/**
 * Request data that can be inspected by an ESTRequestAuthorizer to make
 * authorization decisions.
 *
 * This record type includes fields for data that are common to all
 * enrollment requests, including:
 *
 * - EST "label" path component (if any)
 * - authenticated principal
 * - remote (IP) address of client
 *
 * This type does NOT include the CSR, because some EST endpoints
 * deal with CMS objects rather than PKCS #10 objects.  These objects
 * are passed to the ESTRequestAuthorizer as arguments, alongside the
 * ESTRequestAuthorizationData.
 *
 * @author Fraser Tweedale
 */
class ESTRequestAuthorizationData {

    Principal principal;
    String remoteAddr;
    Optional<String> label;

}
