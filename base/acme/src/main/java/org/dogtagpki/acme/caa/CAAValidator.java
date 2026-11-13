// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

/**
 * Evaluates CAA authorization independently of the enrollment protocol.
 *
 * - The subsystem owns a long-lived validator bound to one issuer policy.
 * - Calls to validate() may run concurrently.
 * - The host supplies final intended names and trusted binding context,
 *   and enforces the decision before issuance.
 * - The validator does not issue certificates or change request/order state.
 * - Limits apply per instance, not across all instances.
 */
public interface CAAValidator extends AutoCloseable {
    /**
     * Closes owned DNS resources. Idempotent and safe alongside active calls;
     * calls after close must not authorize issuance. Decisions already returned
     * are not revoked. Only the subsystem owner closes a shared validator.
     */
    @Override
    void close();

    /**
     * Evaluates all requested names synchronously. Expected DNS failures are
     * reported as ERROR decisions. An exception must also prevent issuance.
     * ALLOW covers only these names, this issuer policy and the stated lifetime;
     * it is not a transferable authorization token for a later request.
     */
    CAADecision validate(CAARequest request);
}
