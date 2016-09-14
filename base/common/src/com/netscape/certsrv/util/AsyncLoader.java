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
    private ReentrantLock loadingLock = new ReentrantLock();
    private Integer numItems = null;
    private int numItemsLoaded = 0;

    /**
     * Acquire the lock as a producer.
     */
    public void startLoading() {
        numItems = null;
        numItemsLoaded = 0;
        loadingLock.lock();
        producerInitialised.countDown();
    }

    /**
     * Increment the number of items loaded by 1.  If the number
     * of items is known and that many items have been loaded,
     * unlock the loader.
     */
    public void increment() {
        numItemsLoaded += 1;
        checkLoadDone();
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
            while (loadingLock.isHeldByCurrentThread())
                loadingLock.unlock();
        }
    }

    public void awaitLoadDone() throws InterruptedException {
        /* A consumer may await upon the Loader immediately after
         * starting the producer.  To ensure that the producer
         * has time to acquire the lock, we use a CountDownLatch.
         */
        producerInitialised.await();
        loadingLock.lock();
        loadingLock.unlock();
    }
}
