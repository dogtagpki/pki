// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.caa;

import java.util.concurrent.Callable;
import java.util.function.Consumer;

/** Test-only driver for the host's explicit check-then-submit sequence. */
public final class TestCAAIssuance {
    private TestCAAIssuance() {
    }

    public static <T> T submit(CAAIssuanceGate gate, CAARequest request,
            Consumer<CAADecision> observer, Callable<T> submission) throws Exception {
        gate.check(request, observer);
        return submission.call();
    }
}
