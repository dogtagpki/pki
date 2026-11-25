// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

/**
 * Test helper supplying the caller-owned lookup budget to standalone DNS
 * adapter tests. It lets those tests exercise the shared deadline and query/
 * alias contract without constructing the policy engine. This is a separate
 * test implementation; CAALookupBudgetTest also exercises the production
 * budget in DefaultCAAValidator. Clock injection allows deterministic deadline
 * checks, and atomic counters support concurrent fixture callers.
 */
public final class TestCAALookupBudget implements CAADNSClient.LookupBudget {
    private final long started;
    private final long timeoutNanos;
    private final Duration queryTimeout;
    private final LongSupplier clock;
    private final AtomicInteger queries;
    private final AtomicInteger aliases;

    public TestCAALookupBudget(CAAPolicy.Limits limits) {
        this(limits, System::nanoTime);
    }

    /**
     * Package-private clock injection for deterministic deadline tests.
     */
    TestCAALookupBudget(CAAPolicy.Limits limits, LongSupplier clock) {
        Objects.requireNonNull(limits);
        this.clock = Objects.requireNonNull(clock);
        started = clock.getAsLong();
        timeoutNanos = limits.totalTimeout().toNanos();
        queryTimeout = limits.queryTimeout();
        queries = new AtomicInteger(limits.maxQueries());
        aliases = new AtomicInteger(limits.maxAliases());
    }

    @Override
    public Duration remaining() {
        long elapsed = clock.getAsLong() - started;
        return elapsed >= timeoutNanos ? Duration.ZERO : Duration.ofNanos(timeoutNanos - elapsed);
    }

    @Override
    public Duration queryTimeout() {
        return queryTimeout;
    }

    @Override
    public void reserveQuery() throws DNSLookupException {
        reserve(queries);
    }

    @Override
    public void reserveAlias() throws DNSLookupException {
        reserve(aliases);
    }

    private void reserve(AtomicInteger allowance) throws DNSLookupException {
        if (Thread.currentThread().isInterrupted()) {
            throw failure(DNSLookupException.Reason.CANCELLED, "CAA lookup interrupted");
        }
        if (remaining().isZero()) {
            throw failure(DNSLookupException.Reason.TIMEOUT, "CAA lookup deadline exceeded");
        }
        // getAndUpdate returns the previous count while atomically decrementing
        // a positive allowance. Zero stays zero, so failed calls cannot wrap it.
        if (allowance.getAndUpdate(value -> value > 0 ? value - 1 : 0) == 0) {
            throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED, "CAA lookup allowance exhausted");
        }
    }

    private static DNSLookupException failure(DNSLookupException.Reason reason, String message) {
        return new DNSLookupException(new DNSLookupException.Failure(reason, message, List.of()));
    }
}
