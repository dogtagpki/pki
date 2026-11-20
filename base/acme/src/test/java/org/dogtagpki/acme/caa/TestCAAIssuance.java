// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.concurrent.Callable;
import java.util.function.Consumer;

/**
 * Test helper representing the consuming subsystem's check-then-submit flow.
 * It lets gate tests observe whether an issuance callback is reached after CAA
 * evaluation, and whether failures prevent that submission. It supplies no
 * additional authorization logic and does not perform enrollment or signing;
 * actual subsystem integration must call the gate before its own issuer.
 */
public final class TestCAAIssuance {
    private TestCAAIssuance() {
    }

    public static <T> T submit(CAAIssuanceGate gate, CAARequest request,
            Consumer<CAADecision> observer, Callable<T> submission) throws Exception {
        gate.check(request, observer);
        return submission.call();
    }
}
