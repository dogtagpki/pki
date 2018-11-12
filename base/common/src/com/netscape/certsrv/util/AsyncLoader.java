// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2016  Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.util;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.locks.ReentrantLock;

/** A locking mechanism for loading or reloading an initially
 * unknown number of items.
 *
 * The "producer" is the thread that loads items, informing the
 * Loader when each item is loaded and how many items there are
 * (when that fact becomes known).
 *
 * Other threads can await the completion of a (re)loading
 * process.
 */
public class AsyncLoader {
    private CountDownLatch producerInitialised = new CountDownLatch(1);
    private GoAwayLock loadingLock = new GoAwayLock();
    private Integer numItems = null;
    private int numItemsLoaded = 0;
    private boolean loading = true;
    private int timeoutSeconds = 0;
    private Timer timer = new Timer("AsyncLoader watchdog");
    private TimerTask watchdog = null;

    /** Create an AsyncLoader with the specified timeout.
     *
     * If timeoutSeconds > 0, startLoading() will start a timer
     * that will forcibly unlock the loader after the specified
     * timeout.
     */
    public AsyncLoader(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    /**
     * Acquire the lock as a producer and reset
     * progress-tracking variables.
     */
    public void startLoading() {
        loadingLock.lock();
        loading = true;
        numItems = null;
        numItemsLoaded = 0;
        producerInitialised.countDown();
        if (timeoutSeconds > 0) {
            if (watchdog != null)
                watchdog.cancel();
            watchdog = new AsyncLoaderWatchdog();
            timer.schedule(watchdog, timeoutSeconds * 1000);
        }
    }

    /**
     * Increment the number of items loaded by 1.  If the number
     * of items is known and that many items have been loaded,
     * unlock the loader.
     *
     * If the loader is not currently loading, does nothing.
     */
    public void increment() {
        if (loading) {
            numItemsLoaded += 1;
            checkLoadDone();
        }
    }

    /**
     * Set the number of items.  If the number of items already
     * loaded is equal to or greater than the number, unlock the
     * loader.
     */
    public void setNumItems(Integer n) {
        numItems = n;
        checkLoadDone();
    }

    private void checkLoadDone() {
        if (numItems != null && numItemsLoaded >= numItems) {
            watchdog.cancel();
            loading = false;
            while (loadingLock.isHeldByCurrentThread())
                loadingLock.unlock();
        }
    }

    /**
     * Wait upon the consumer to finish loading items.
     *
     * @throws InterruptedException if the thread is interrupted
     * while waiting for the loading lock.  This can happen due
     * to timeout.
     */
    public void awaitLoadDone() throws InterruptedException {
        /* A consumer may await upon the Loader immediately after
         * starting the producer.  To ensure that the producer
         * has time to acquire the lock, we use a CountDownLatch
         * that only the producer can release (in 'startLoading').
         */
        if (loading) {
            producerInitialised.await();
            loadingLock.lockInterruptibly();
            loadingLock.unlock();
        }
    }

    /** Forcibly unlock this AsyncLoader.
     *
     * There's no way we can safely interrupt the producer to
     * release the loadingLock.  So here's what we do.
     *
     * - Interrupt all threads that are waiting on the lock.
     * - Set loading = false so that future call to awaitLoadDone()
     *   return immediately.
     *
     * Upon subseqent re-loads (e.g. due to loss and reesablishment
     * of LDAP persistent search), the producer thread will call
     * startLoading() again, which will increment the producer's
     * hold count.  That's OK because when the unlock condition is
     * met, checkLoadDone() will call loadingLock.unlock() as many
     * times as needed to effect the unlock.
     *
     * This method DOES NOT interrupt threads waiting on the
     * producerInitialised CountDownLatch.  The producer MUST call
     * startLoading() which will acquire the loading lock then
     * release the CountDownLatch.
     */
    private void forceUnlock() {
        loading = false;
        loadingLock.interruptWaitingThreads();
    }

    /** Subclass of ReentrantLock that can tell waiting threads
     * to go away (by interrupting them).  Awaiters must use
     * lockInterruptibly() to acquire the lock.
     *
     * This needed to be a subclass of ReentrantLock because
     * ReentrantLock.getQueuedThreads() has visibility 'protected'.
     */
    private static class GoAwayLock extends ReentrantLock {
        public void interruptWaitingThreads() {
            for (Thread thread : getQueuedThreads()) {
                thread.interrupt();
            }
        }
    }

    private class AsyncLoaderWatchdog extends TimerTask {
        public void run() {
            forceUnlock();
        }
    }
}
