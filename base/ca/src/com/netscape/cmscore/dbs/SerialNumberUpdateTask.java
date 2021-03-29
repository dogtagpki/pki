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
package com.netscape.cmscore.dbs;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import com.netscape.cmscore.request.RequestRepository;

public class SerialNumberUpdateTask implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SerialNumberUpdateTask.class);

    CertificateRepository certRepository;
    RequestRepository requestRepository;

    int interval;

    ScheduledExecutorService executorService;

    public SerialNumberUpdateTask(
            CertificateRepository certRepository,
            RequestRepository requestRepository,
            int interval) {

        this.certRepository = certRepository;
        this.requestRepository = requestRepository;
        this.interval = interval;
    }

    public void start() {
        // schedule task to run immediately and repeat after specified interval
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            public Thread newThread(Runnable r) {
                return new Thread(r, "SerialNumberUpdateTask");
            }
        });
        executorService.scheduleWithFixedDelay(this, 0, interval, TimeUnit.SECONDS);
    }

    public synchronized void updateSerialNumbers() throws Exception {

        logger.info("SerialNumberUpdateTask: Updating serial number counter");
        certRepository.updateCounter();

        logger.info("SerialNumberUpdateTask: Checking serial number ranges");
        certRepository.checkRanges();

        logger.info("SerialNumberUpdateTask: Checking request ID ranges");
        requestRepository.checkRanges();
    }

    public void run() {
        try {
            updateSerialNumbers();

        } catch (Exception e) {
            logger.warn("SerialNumberUpdateTask: " + e.getMessage(), e);
        }
    }

    public void stop() {
        // shutdown executorService without interrupting running task
        if (executorService != null) executorService.shutdown();
    }
}
