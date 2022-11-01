//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.job;

import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.jobs.Job;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.jobs.JobConfig;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestList;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;

/**
 * @author Endi S. Dewata
 */
public class PruningJob extends Job implements IExtendedPluginInfo {

    int certRetentionTime;
    int certRetentionUnit;
    int requestRetentionTime;
    int requestRetentionUnit;

    CertificateRepository certRepository;
    RequestRepository requestRepository;

    @Override
    public String[] getConfigParams() {
        return new String[] {
                "enabled",
                "cron",
                "certRetentionTime",
                "certRetentionUnit",
                "requestRetentionTime",
                "requestRetentionUnit"
        };
    }

    @Override
    public String[] getExtendedPluginInfo() {
        return new String[] {
                IExtendedPluginInfo.HELP_TEXT +
                        "; A job that removes expired certificates and incomplete requests after" +
                        " the retention period",
                "cron;string;Format: minute hour dayOfMonth month " +
                        "dayOfWeek. Use '*' for 'every'. For dayOfWeek, 0 is Sunday",
                "enabled;boolean;Enable this plugin",
                "certRetentionTime;integer;Certificate retention time (default: 30)",
                "certRetentionUnit;integer;Certificate retention unit: year, month, day (default), hour, minute",
                "requestRetentionTime;integer;Request retention time (default: 30)",
                "requestRetentionUnit;integer;Request retention unit: year, month, day (default), hour, minute",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-jobrules-pruningjobs",
        };
    }

    int parseRetentionUnit(String unit) throws EBaseException {

        if (unit.equals("year")) {
            return Calendar.YEAR;

        } else if (unit.equals("month")) {
            return Calendar.MONTH;

        } else if (unit.equals("day") || unit.equals("")) {
            return Calendar.DAY_OF_YEAR;

        } else if (unit.equals("hour")) {
            return Calendar.HOUR_OF_DAY;

        } else if (unit.equals("minute")) {
            return Calendar.MINUTE;

        } else {
            throw new EBaseException("Invalid retention unit: " + unit);
        }
    }

    @Override
    public void init(JobsScheduler scheduler, String id, String implName, JobConfig config) throws EBaseException {

        super.init(scheduler, id, implName, config);

        CAEngine engine = CAEngine.getInstance();
        requestRepository = engine.getRequestRepository();
        certRepository = engine.getCertificateRepository();

        String certRetentionTimeStr = config.getString("certRetentionTime", "30");
        logger.info("PruningJob: - cert retention time: " + certRetentionTimeStr);
        certRetentionTime = Integer.parseInt(certRetentionTimeStr);

        String certRetentionUnitStr = config.getString("certRetentionUnit", "day");
        logger.info("PruningJob: - cert retention unit: " + certRetentionUnitStr);
        certRetentionUnit = parseRetentionUnit(certRetentionUnitStr);

        String requestRetentionTimeStr = config.getString("requestRetentionTime", "30");
        logger.info("PruningJob: - request retention time: " + requestRetentionTimeStr);
        requestRetentionTime = Integer.parseInt(requestRetentionTimeStr);

        String requestRetentionUnitStr = config.getString("requestRetentionUnit", "day");
        logger.info("PruningJob: - request retention unit: " + requestRetentionUnitStr);
        requestRetentionUnit = parseRetentionUnit(requestRetentionUnitStr);
    }

    public void pruneCertRecord(CertRecord certRecord) throws Exception {

        X509CertImpl cert = certRecord.getCertificate();
        CertId certID = new CertId(cert.getSerialNumber());

        logger.info("PruningJob: Removing cert " + certID.toHexString());
        certRepository.deleteCertificateRecord(cert.getSerialNumber());

        MetaInfo metaInfo = (MetaInfo) certRecord.get(CertRecord.ATTR_META_INFO);
        if (metaInfo == null) {
            logger.info("PruningJob: Cert " + certID.toHexString() + " has no metadata");
            return;
        }

        String requestIDString = (String) metaInfo.get(CertRecord.META_REQUEST_ID);
        if (requestIDString == null) {
            logger.info("PruningJob: Cert " + certID.toHexString() + " has no request");
            return;
        }

        RequestId requestID = new RequestId(requestIDString);
        logger.info("PruningJob: Removing request " + requestID.toHexString() + " for cert " + certID.toHexString());

        requestRepository.removeRequest(requestID);
    }

    public void pruneCertRecords(Calendar calendar) throws EBaseException {

        Calendar pruningCalendar = (Calendar) calendar.clone();
        pruningCalendar.add(certRetentionUnit, -certRetentionTime);

        Date pruningTime = pruningCalendar.getTime();
        logger.info("PruningJob: Pruning certs expired before " + pruningTime);

        long time = pruningTime.getTime();

        String filter = "(&(x509Cert.notAfter<=" + time + ")(!(x509Cert.notAfter=" + time + ")))";
        logger.info("PruningJob: - filter: " + filter);

        Enumeration<Object> certRecords = certRepository.findCertRecs(filter);

        while (certRecords.hasMoreElements()) {
            CertRecord certRecord = (CertRecord) certRecords.nextElement();

            CertId certID = new CertId(certRecord.getSerialNumber());
            logger.info("PruningJob: Pruning cert " + certID.toHexString());
            logger.info("PruningJob: - expired: " + certRecord.getNotAfter());

            try {
                pruneCertRecord(certRecord);
            } catch (Exception e) {
                logger.warn("Unable to prune cert " + certID.toHexString() + ": " + e.getMessage(), e);
            }
        }
    }

    public void pruneRequestRecords(Calendar calendar) throws EBaseException {

        Calendar pruningCalendar = (Calendar) calendar.clone();
        pruningCalendar.add(requestRetentionUnit, -requestRetentionTime);

        Date pruningTime = pruningCalendar.getTime();
        logger.info("PruningJob: Pruning incomplete requests last modified before " + pruningTime);

        long time = pruningTime.getTime();

        String filter = "(&" +
                "(!(" + RequestRecord.ATTR_REQUEST_STATE + "=" + RequestStatus.COMPLETE + "))" +
                "(" + RequestRecord.ATTR_MODIFY_TIME + "<=" + time + ")" +
                "(!(" + RequestRecord.ATTR_MODIFY_TIME + "=" + time + ")))";
        logger.info("PruningJob: - filter: " + filter);

        RequestList requestRecords = requestRepository.listRequestsByFilter(filter);

        while (requestRecords.hasMoreElements()) {
            RequestId requestID = requestRecords.nextElement();
            logger.info("PruningJob: Pruning request " + requestID.toHexString());

            Request request = requestRepository.readRequest(requestID);
            logger.info("PruningJob: - status: " + request.getRequestStatus());
            logger.info("PruningJob: - last modified: " + request.getModificationTime());

            try {
                requestRepository.removeRequest(requestID);
            } catch (EBaseException e) {
                logger.warn("Unable to prune cert " + requestID.toHexString() + ": " + e.getMessage(), e);
            }
        }
    }

    @Override
    public void run() {
        Calendar calendar = Calendar.getInstance();
        Date time = calendar.getTime();
        logger.info("PruningJob: Running " + mId + " job at " + time);

        IDGenerator requestIDGenerator = requestRepository.getIDGenerator();
        if (requestIDGenerator != IDGenerator.RANDOM) {
            String message = "Unsupported request ID generator for pruning: " + requestIDGenerator;
            logger.error(message);
            throw new RuntimeException(message);
        }

        IDGenerator certIDGenerator = certRepository.getIDGenerator();
        if (certIDGenerator != IDGenerator.RANDOM) {
            String message = "Unsupported certificate ID generator for pruning: " + certIDGenerator;
            logger.error(message);
            throw new RuntimeException(message);
        }

        try {
            pruneCertRecords(calendar);
        } catch (EBaseException e) {
            logger.warn("PruningJob: Unable to prune certificates: " + e.getMessage(), e);
        }

        try {
            pruneRequestRecords(calendar);
        } catch (EBaseException e) {
            logger.warn("PruningJob: Unable to prune requests: " + e.getMessage(), e);
        }
    }
}
