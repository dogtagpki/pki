//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.ca;

import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.Timer;
import java.util.TimerTask;

import com.netscape.certsrv.ca.AuthorityID;

/**
 * Wrapper around a Timer to execute key retrieval attempts,
 * rescheduling failed attempts with backoff.
 */
public class KeyRetrieverWorker {

    public final static org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(KeyRetrieverWorker.class);

    private SortedSet<AuthorityID> aidsInQueue;

    protected Timer timer;

    /** Constructor initialises the queue and **starts the thread**.
     *
     * Only one KeyRetrieverWorker should ever be constructed.
     */
    public KeyRetrieverWorker() {
        aidsInQueue = Collections.synchronizedSortedSet(new TreeSet());
        timer = new Timer("KeyRetrieverWorker");
    }

    /** Register a key retriever with the worker thread.
     *
     * Following registration, no further action is required
     * by the caller.  The worker thread takes care of retrieval
     * attempts and backoff.
     */
    public void requestKeyRetrieval(KeyRetrieverRunner krr) {
        AuthorityID aid = krr.getAuthorityID();
        if (aidsInQueue.contains(aid)) {
            logger.info("KeyRetriever already enqueued for authority " + aid);
            return;
        }

        logger.info("Queuing KeyRetriever for authority " + aid);
        aidsInQueue.add(aid);
        Request req = new Request(krr, 10000 /* initial backoff = 10s */);
        timer.schedule(req, 0);     // attempt immediately
    }

    private class Request extends TimerTask {
        KeyRetrieverRunner krr;
        long backoff_ms;

        public Request(KeyRetrieverRunner krr, long backoff_ms) {
            this.krr = krr;
            this.backoff_ms = backoff_ms;
        }

        public void run() {
            AuthorityID aid = krr.getAuthorityID();
            logger.debug(aid + ": attempt retrieval");
            if (krr.attemptRetrieval()) {
                logger.info(aid + ": successfully retrieved key");
                aidsInQueue.remove(aid);
            } else {
                logger.info(aid + ": failed to retrieve key; try again after "
                        + backoff_ms / 1000 + "s");
                long new_backoff = backoff_ms + backoff_ms / 2;
                // cannot reschedule "this" -> IllegalStateException;
                // therefore create a new Request and schedule that.
                timer.schedule(new Request(krr, new_backoff), backoff_ms);
            }
        }
    }

}
