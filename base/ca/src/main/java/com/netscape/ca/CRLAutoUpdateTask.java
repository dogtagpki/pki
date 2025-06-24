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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.ca;

import com.netscape.ca.CRLIssuingPoint.CRLIssuingPointStatus;
import com.netscape.certsrv.base.EBaseException;

/**
 * @author awnuk
 * @author lhsiao
 * @author galperin
 */
public class CRLAutoUpdateTask implements Runnable {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CRLAutoUpdateTask.class);

    CRLIssuingPoint ip;

    CRLAutoUpdateTask(CRLIssuingPoint ip) {
        this.ip = ip;
    }

    public void handleUnexpectedFailure(int loopCounter, long timeOfUnexpectedFailure) {

        logger.info("CRLAutoUpdateTask: Handling unexpected failure");
        logger.info("CRLAutoUpdateTask: - loop counter: " + loopCounter);

        if (loopCounter <= ip.mUnexpectedExceptionLoopMax) {
            logger.info("CRLAutoUpdateTask: Max loop not reached, no wait time");
            return;
        }

        logger.info("CRLAutoUpdateTask: Max loop reached, slowdown procedure ensues");

        long now = System.currentTimeMillis();
        logger.info("CRLAutoUpdateTask: - now: " + now);
        logger.info("CRLAutoUpdateTask: - time of unexpected failure: " + timeOfUnexpectedFailure);

        long timeLapse = now - timeOfUnexpectedFailure;
        logger.info("CRLAutoUpdateTask: - time lapse: " + timeLapse);

        long waitTime = ip.mUnexpectedExceptionWaitTime - timeLapse;
        logger.info("CRLAutoUpdateTask: Wait time after last failure:" + waitTime);

        if (waitTime <= 0) {
            logger.info("CRLAutoUpdateTask: No wait after failure");
            return;
        }

        logger.info("CRLAutoUpdateTask: Waiting for " + waitTime + " ms");

        try {
            ip.wait(waitTime);

        } catch (InterruptedException e) {
            logger.error("CRLAutoUpdateTask: " + e.getMessage(), e);
        }

        // timeOfUnexpectedFailure will be reset again if it still fails
    }

    /**
     * Defines auto-update logic used by worker thread.
     */
    @Override
    public void run() {
        // mechanism to slow down the infinite loop when depending
        // components are not available: e.g. Directory server, HSM
        boolean unexpectedFailure = false;
        long timeOfUnexpectedFailure = 0;
        int loopCounter = 0;

        try {
            while (ip.mEnable && (
                      (ip.mEnableCRLCache && ip.mCacheUpdateInterval > 0) ||
                      (ip.mInitialized == CRLIssuingPointStatus.NotInitialized) ||
                      ip.mDoLastAutoUpdate ||
                      (ip.mEnableCRLUpdates && (
                          (ip.mEnableDailyUpdates && ip.mDailyUpdates != null && ip.mTimeListSize > 0) ||
                          (ip.mEnableUpdateFreq && ip.mAutoUpdateInterval > 0) ||
                          ip.mDoManualUpdate
                      ))
                  )) {

                synchronized (ip) {
                    long delay = 0;
                    long delay2 = 0;
                    boolean doCacheUpdate = false;
                    boolean scheduledUpdates = ip.mEnableCRLUpdates && (
                            (ip.mEnableDailyUpdates && ip.mDailyUpdates != null && ip.mTimeListSize > 0) ||
                            (ip.mEnableUpdateFreq && ip.mAutoUpdateInterval > 0)
                    );

                    if (ip.mInitialized == CRLIssuingPointStatus.NotInitialized) {
                        ip.initCRL();
                    }

                    if ((ip.mEnableCRLUpdates && ip.mDoManualUpdate) || ip.mDoLastAutoUpdate) {
                        delay = 0;
                    } else if (scheduledUpdates) {
                        delay = ip.findNextUpdate(true, false);
                    }

                    if (ip.mEnableCRLCache && ip.mCacheUpdateInterval > 0) {
                        delay2 = ip.mLastCacheUpdate + ip.mCacheUpdateInterval - System.currentTimeMillis();
                        if (delay2 < delay ||
                                (!(scheduledUpdates || ip.mDoLastAutoUpdate ||
                                (ip.mEnableCRLUpdates && ip.mDoManualUpdate)))) {
                            delay = delay2;
                            if (delay <= 0) {
                                doCacheUpdate = true;
                                ip.mLastCacheUpdate = System.currentTimeMillis();
                            }
                        }
                    }

                    if (delay > 0) {
                        try {
                            ip.wait(delay);
                        } catch (InterruptedException e) {
                            logger.error("CRLAutoUpdateTask: " + e.getMessage(), e);
                        }

                    } else {
                        /*
                         * handle last failure so we don't get into
                         * non-delayed loop
                         */
                        if (unexpectedFailure) {
                            // it gets mUnexpectedExceptionLoopMax tries
                            loopCounter++;
                            handleUnexpectedFailure(loopCounter, timeOfUnexpectedFailure);
                        }

                        logger.debug("CRLAutoUpdateTask: Before CRL generation");
                        try {
                            if (doCacheUpdate) {
                                logger.info("CRLAutoUpdateTask: Updating CRL cache");
                                ip.updateCRLCacheRepository();
                            } else if (ip.mAutoUpdateInterval > 0 || ip.mDoLastAutoUpdate || ip.mDoManualUpdate) {
                                logger.info("CRLAutoUpdateTask: Updating CRL");
                                ip.updateCRL();
                            }

                            // reset if no exception
                            if (unexpectedFailure) {
                                logger.debug("CRLAutoUpdateTask: reset unexpectedFailure values if no exception");
                                unexpectedFailure = false;
                                timeOfUnexpectedFailure = 0;
                                loopCounter = 0;
                            }

                        } catch (Exception e) {
                            logger.warn("CRLAutoUpdateTask: Unable to update " + (doCacheUpdate ? "CRL cache" : "CRL") + ": " + e.getMessage(), e);
                            unexpectedFailure = true;
                            timeOfUnexpectedFailure = System.currentTimeMillis();
                        }

                        // put this here to prevent continuous loop if internal
                        // db is down.

                        if (ip.mDoLastAutoUpdate) {
                            logger.debug("CRLAutoUpdateTask: mDoLastAutoUpdate set to false");
                            ip.mDoLastAutoUpdate = false;
                        }

                        if (ip.mDoManualUpdate) {
                            logger.debug("CRLAutoUpdateTask: mDoManualUpdate set to false");
                            ip.mDoManualUpdate = false;
                            ip.mSignatureAlgorithmForManualUpdate = null;
                        }
                    }

                }
            }
        } catch (EBaseException e) {
            logger.error("CRLAutoUpdateTask: " + e.getMessage(), e);
        }

        logger.debug("CRLAutoUpdateTask: out of the while loop");
        ip.mUpdateThread = null;
    }
}
