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

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertRecordProcessor;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmscore.apps.CMS;

public class CertStatusUpdateTask implements Runnable {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertStatusUpdateTask.class);

    CertificateRepository repository;

    int interval;
    int pageSize = 200;
    int maxRecords = 1000000;

    ScheduledExecutorService executorService;

    public CertStatusUpdateTask(
            CertificateRepository repository,
            int interval,
            int pageSize,
            int maxRecords) {

        this.repository = repository;
        this.interval = interval;
        this.pageSize = pageSize;
        this.maxRecords = maxRecords;
    }

    public void start() {
        // schedule task to run immediately and repeat after specified interval
        executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                return new Thread(r, "CertStatusUpdateTask");
            }
        });
        executorService.scheduleWithFixedDelay(this, 0, interval, TimeUnit.SECONDS);
    }

    /**
     * Updates a certificate status from INVALID to VALID
     * if a certificate becomes valid.
     */
    public void updateInvalidCertificates() throws Exception {

        logger.info("CertStatusUpdateTask: Updating invalid certs to valid");
        Date now = new Date();

        RecordPagedList<CertRecord> recordList = repository.getInvalidCertsByNotBeforeDate(now);
        Iterator<CertRecord> certRecIterator = recordList.iterator();

        if (!certRecIterator.hasNext()) {
            logger.debug("CertStatusUpdateTask: No invalid certs");
            return;
        }

        ArrayList<CertId> list = new ArrayList<>();
        int recs = 0;
        while (certRecIterator.hasNext() && recs < maxRecords) {
            CertRecord certRecord = certRecIterator.next();
            CertId certID = new CertId(certRecord.getSerialNumber());

            Date notBefore = certRecord.getNotBefore();
            if (notBefore.after(now)) {
                logger.debug("CertStatusUpdateTask: Cert {} not yet valid", certID.toHexString());
                continue;
            }

            logger.debug("CertStatusUpdateTask: Cert {} has become valid", certID.toHexString());
            list.add(certID);
            recs++;
        }
        logger.debug("CertStatusUpdateTask: - invalid list size: {}", list.size());
        repository.updateStatus(list, CertRecord.STATUS_VALID);
    }

    /**
     * Updates a certificate status from VALID to EXPIRED
     * if a certificate becomes expired.
     */
    public void updateValidCertificates() throws Exception {

        logger.info("CertStatusUpdateTask: Updating valid certs to expired");
        Date now = new Date();

        RecordPagedList<CertRecord> recordList = repository.getValidCertsByNotAfterDate(now);
        Iterator<CertRecord> certRecIterator = recordList.iterator();

        if (!certRecIterator.hasNext()) {
            logger.debug("CertStatusUpdateTask: No invalid certs");
            return;
        }

        ArrayList<CertId> list = new ArrayList<>();
        int recs = 0;
        while (certRecIterator.hasNext() && recs < maxRecords) {
            CertRecord certRecord = certRecIterator.next();
            CertId certID = new CertId(certRecord.getSerialNumber());

            Date notAfter = certRecord.getNotAfter();
            if (notAfter.after(now)) {
                logger.debug("CertStatusUpdateTask: Cert {} not yet expired", certID.toHexString());
                continue;
            }

            logger.debug("CertStatusUpdateTask: Cert {} has become expired", certID.toHexString());
            list.add(certID);
            recs++;
        }
        logger.debug("CertStatusUpdateTask: - valid list size: {}", list.size());
        repository.updateStatus(list, CertRecord.STATUS_EXPIRED);
    }
    /**
     * Updates a certificate status from REVOKED to REVOKED_EXPIRED
     * if a revoked certificate becomes expired.
     */
    public void updateRevokedExpiredCertificates() throws EBaseException {

        logger.info("CertStatusUpdateTask: Updating revoked certs to expired");
        CAEngine engine = CAEngine.getInstance();
        Date now = new Date();

        RecordPagedList<CertRecord> recordList = repository.getRevokedCertsByNotAfterDate(now);
        Iterator<CertRecord> certRecIterator = recordList.iterator();


        if (!certRecIterator.hasNext()) {
            logger.debug("CertStatusUpdateTask: No invalid certs");
            return;
        }

        ArrayList<CertId> list = new ArrayList<>();
        int recs = 0;
        while (certRecIterator.hasNext() && recs < maxRecords) {
            CertRecord certRecord = certRecIterator.next();
            CertId certID = new CertId(certRecord.getSerialNumber());

            Date notAfter = certRecord.getNotAfter();
            if (notAfter.after(now)) {
                logger.debug("CertStatusUpdateTask: Cert {} not yet expired", certID.toHexString());
                continue;
            }

            logger.debug("CertStatusUpdateTask: Cert {} has become expired", certID.toHexString());
            list.add(certID);
            recs++;
        }
        logger.debug("CertStatusUpdateTask: - valid list size: {}", list.size());
        repository.updateStatus(list, CertRecord.STATUS_REVOKED_EXPIRED);

        // notify all CRL issuing points about revoked and expired certificates

        for (int i = 0; i < list.size(); i++) {
            CertId certID = list.get(i);

            for (CRLIssuingPoint issuingPoint : engine.getCRLIssuingPoints()) {
                issuingPoint.addExpiredCert(certID.toBigInteger());
            }
        }
    }

    /**
     * Updates certificate status.
     *
     * This code and processRevokedCerts() are mutually exclusive.
     *
     * @exception EBaseException failed to update
     */
    public synchronized void updateCertStatus() throws Exception {

        logger.info("CertStatusUpdateTask: Updating cert status");

        logger.debug(CMS.getLogMessage("CMSCORE_DBS_START_VALID_SEARCH"));
        updateInvalidCertificates();
        logger.debug(CMS.getLogMessage("CMSCORE_DBS_FINISH_VALID_SEARCH"));

        logger.debug(CMS.getLogMessage("CMSCORE_DBS_START_EXPIRED_SEARCH"));
        updateValidCertificates();
        logger.debug(CMS.getLogMessage("CMSCORE_DBS_FINISH_EXPIRED_SEARCH"));

        logger.debug(CMS.getLogMessage("CMSCORE_DBS_START_REVOKED_EXPIRED_SEARCH"));
        updateRevokedExpiredCertificates();
        logger.debug(CMS.getLogMessage("CMSCORE_DBS_FINISH_REVOKED_EXPIRED_SEARCH"));
    }

    /**
     * Processes revoked certificates.
     *
     * This code and updateCertStatus() are mutually exclusive.
     */
    public synchronized void processRevokedCerts(
            CertRecordProcessor cp,
            String filter,
            int pageSize) throws EBaseException {

        logger.info("CertStatusUpdateTask: Processing revoked certs");

        RecordPagedList<CertRecord> list = repository.findPagedCertRecords(
                filter,
                new String[] {
                        CertRecord.ATTR_ID, CertRecord.ATTR_REVO_INFO, "objectclass"
                },
                null);
        for (CertRecord certRecord: list) {
            cp.process(certRecord);
        }
        logger.info("CertStatusUpdateTask: Done processing revoked certs");
    }

    @Override
    public void run() {
        try {
            updateCertStatus();

        } catch (Exception e) {
            logger.warn("CertStatusUpdateTask: " + e.getMessage(), e);
        }
    }

    public void stop() {
        // shutdown executorService without interrupting running task
        if (executorService != null) executorService.shutdown();
    }
}
