// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/** Tests the shared fixture's deadline, interruption and allowance behavior. */
public class CAALookupBudgetTest {

    @Test
    void sharesQueryAllowanceAcrossFollowupsWithoutResettingDeadline() throws Exception {
        AtomicLong clock = new AtomicLong(100);
        CAAPolicy.Limits limits = new CAAPolicy.Limits(Duration.ofNanos(100), Duration.ofNanos(20), 2, 1, 1);
        var budget = new TestCAALookupBudget(limits, clock::get);
        budget.reserveQuery();
        clock.addAndGet(30);
        budget.reserveQuery();
        assertEquals(Duration.ofNanos(70), budget.remaining());
        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                assertThrows(DNSLookupException.class, budget::reserveQuery).failure().reason());
        budget.reserveAlias();
        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                assertThrows(DNSLookupException.class, budget::reserveAlias).failure().reason());
    }

    @Test
    void expiresAtTheMonotonicDeadlineAndPreservesInterruption() {
        AtomicLong clock = new AtomicLong(100);
        var budget = new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofNanos(100),
                Duration.ofNanos(20), 2, 2, 1), clock::get);
        clock.addAndGet(100);
        assertEquals(Duration.ZERO, budget.remaining());
        assertEquals(DNSLookupException.Reason.TIMEOUT,
                assertThrows(DNSLookupException.class, budget::reserveQuery).failure().reason());
        Thread.currentThread().interrupt();
        try {
            assertEquals(DNSLookupException.Reason.CANCELLED,
                    assertThrows(DNSLookupException.class, budget::reserveAlias).failure().reason());
        } finally {
            Thread.interrupted();
        }
    }

}
