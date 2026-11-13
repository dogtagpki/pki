// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

/**
 * Tests the resource accounting that bounds DNS work during a CAA attempt.
 * The production budget supplies a shared monotonic deadline and query/alias
 * allowances to discovery and DNS adapters. These checks establish when work
 * must stop, including on interruption; they do not test DNS TTLs or decision
 * freshness. Controllable clocks exercise the production budget and the
 * standalone adapter-test budget without sleeping.
 */
public class CAALookupBudgetTest {

    /**
     * Use a controllable nanosecond clock, reserve two queries and advance time.
     * Reservations must share one deadline; query and alias counts exhaust separately.
     */
    @Test
    void sharesQueryAllowanceAcrossFollowupsWithoutResettingDeadline() throws Exception {
        // clock::get implements LongSupplier: the budget reads this value in
        // place of System.nanoTime(), so no sleep or real-time race is needed.
        AtomicLong clock = new AtomicLong(100);
        CAAPolicy.Limits limits = new CAAPolicy.Limits(Duration.ofNanos(100), Duration.ofNanos(20), 2, 1, 1);
        TestCAALookupBudget budget = new TestCAALookupBudget(limits, clock::get);
        budget.reserveQuery();
        // Move time forward explicitly; reserveQuery() must not restart it.
        clock.addAndGet(30);
        budget.reserveQuery();

        assertEquals(Duration.ofNanos(70), budget.remaining());
        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                assertThrows(DNSLookupException.class, budget::reserveQuery).failure().reason());
        budget.reserveAlias();

        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                assertThrows(DNSLookupException.class, budget::reserveAlias).failure().reason());
    }

    /**
     * Advance the fake clock exactly to expiry, then interrupt the caller.
     * The budget must report TIMEOUT first and CANCELLED once interruption is set.
     */
    @Test
    void expiresAtTheMonotonicDeadlineAndPreservesInterruption() {
        AtomicLong clock = new AtomicLong(100);
        TestCAALookupBudget budget = new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofNanos(100),
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
            // Unlike isInterrupted(), this reads AND clears the flag. Restore
            // the JUnit worker thread before another test uses it.
            Thread.interrupted();
        }
    }

    /**
     * Advance the actual production budget to just before, exactly at and past
     * its deadline. Query reservations must not restart the monotonic clock.
     */
    @Test
    void productionBudgetExpiresAtItsOriginalDeadline() throws Exception {
        AtomicLong clock = new AtomicLong(100);
        CAAPolicy.Limits limits = new CAAPolicy.Limits(
                Duration.ofNanos(100), Duration.ofNanos(20), 3, 1, 1);
        DefaultCAAValidator.Budget budget = new DefaultCAAValidator.Budget(limits, clock::get);
        budget.reserveQuery();
        clock.addAndGet(99);
        budget.reserveQuery();

        assertEquals(Duration.ofNanos(1), budget.remaining());
        assertEquals(Duration.ofNanos(20), budget.queryTimeout());
        clock.incrementAndGet();

        assertEquals(Duration.ZERO, budget.remaining());

        DNSLookupException expired = assertThrows(DNSLookupException.class, budget::check);
        assertEquals(DNSLookupException.Reason.TIMEOUT, expired.failure().reason());
        clock.incrementAndGet();

        assertEquals(Duration.ZERO, budget.remaining());
        assertThrows(DNSLookupException.class, budget::reserveQuery);
        assertThrows(DNSLookupException.class, budget::reserveAlias);
    }

    /**
     * Cross the signed long boundary without exhausting the timeout first.
     * Subtracting monotonic readings must still expire at exactly 100 ns.
     */
    @Test
    void productionDeadlineSurvivesSignedNanosecondWraparound() throws Exception {
        AtomicLong clock = new AtomicLong(Long.MAX_VALUE - 50);
        CAAPolicy.Limits limits = new CAAPolicy.Limits(
                Duration.ofNanos(100), Duration.ofNanos(20), 2, 1, 1);
        DefaultCAAValidator.Budget budget = new DefaultCAAValidator.Budget(limits, clock::get);
        clock.addAndGet(99);

        assertEquals(Duration.ofNanos(1), budget.remaining());
        budget.check();
        clock.incrementAndGet();

        assertEquals(Duration.ZERO, budget.remaining());
        DNSLookupException error = assertThrows(DNSLookupException.class, budget::check);
        assertEquals(DNSLookupException.Reason.TIMEOUT, error.failure().reason());
    }

    /**
     * Exhaust the production query/alias allowances independently, then
     * interrupt the caller. The budget must preserve the interruption flag.
     */
    @Test
    void productionBudgetEnforcesQueryAliasAndInterruptionLimits() throws Exception {
        AtomicLong clock = new AtomicLong(100);
        CAAPolicy.Limits limits = new CAAPolicy.Limits(
                Duration.ofNanos(100), Duration.ofNanos(20), 1, 1, 1);
        DefaultCAAValidator.Budget budget = new DefaultCAAValidator.Budget(limits, clock::get);
        budget.reserveQuery();

        DNSLookupException queryLimit = assertThrows(DNSLookupException.class, budget::reserveQuery);
        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, queryLimit.failure().reason());
        budget.reserveAlias();

        DNSLookupException aliasLimit = assertThrows(DNSLookupException.class, budget::reserveAlias);
        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, aliasLimit.failure().reason());

        Thread.currentThread().interrupt();

        try {
            DNSLookupException interrupted = assertThrows(DNSLookupException.class, budget::check);
            assertEquals(DNSLookupException.Reason.CANCELLED, interrupted.failure().reason());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }
}
