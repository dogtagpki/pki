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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Locale;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.InvalidityDateExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CertStatusChangeRequestEvent;
import com.netscape.certsrv.logging.event.CertStatusChangeRequestProcessedEvent;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class RevocationProcessor extends CertProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RevocationProcessor.class);

    public final static String REVOKE = "revoke";
    public final static String ON_HOLD = "on-hold";
    public final static String OFF_HOLD = "off-hold";

    long startTime;

    CertificateAuthority authority;
    CertificateRepository repo;
    RequestQueue requestQueue;
    CAPublisherProcessor publisherProcessor;

    String initiative;
    CertId serialNumber;
    RevocationReason revocationReason;
    Date invalidityDate;
    String comments;
    String requestType;

    CRLExtensions entryExtn;
    Collection<X509CertImpl> certificates = new ArrayList<>();
    Collection<RevokedCertImpl> revCertImpls = new ArrayList<>();
    Request request;
    RequestStatus requestStatus;

    public RevocationProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    public CertificateAuthority getAuthority() {
        return authority;
    }

    public void setAuthority(CertificateAuthority authority) {
        this.authority = authority;

        CAEngine engine = CAEngine.getInstance();
        repo = engine.getCertificateRepository();
        requestQueue = engine.getRequestQueue();
        publisherProcessor = engine.getPublisherProcessor();
    }

    public long getStartTime() {
        return startTime;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public String getInitiative() {
        return initiative;
    }

    public void setInitiative(String initiative) {
        this.initiative = initiative;
    }

    public CertId getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(CertId serialNumber) {
        this.serialNumber = serialNumber;
    }

    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    public Date getInvalidityDate() {
        return invalidityDate;
    }

    public void setInvalidityDate(Date invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    public String getComments() {
        return comments;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    public String getRequestType() {
        return requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    public RequestStatus getRequestStatus() {
        return requestStatus;
    }

    public void setRequestStatus(RequestStatus requestStatus) {
        this.requestStatus = requestStatus;
    }

    public void addCertificate(X509CertImpl cert) {
        certificates.add(cert);
    }

    public Collection<X509CertImpl> getCertificates() {
        return certificates;
    }

    public Request getRequest() {
        return request;
    }

    public boolean isMemberOfSubsystemGroup(X509Certificate clientCert) {

        if (clientCert == null) {
            return false;
        }

        try {
            X509Certificate certChain[] = new X509Certificate[1];
            certChain[0] = clientCert;

            User user = ul.locateUser(new Certificates(certChain));
            return ug.isMemberOf(user, "Subsystem Group");

        } catch (Exception e) {
            logger.warn("RevocationProcessor:  Failed to map certificate '" +
                    clientCert.getSubjectDN().getName() + "' to user: " + e.getMessage(), e);
            return false;
        }
    }

    public void validateCertificateToRevoke(String subjectDN, CertRecord targetRecord, boolean revokingCACert)
                throws EBaseException {

        X509CertImpl targetCert = targetRecord.getCertificate();
        BigInteger targetSerialNumber = targetCert.getSerialNumber();
        Principal targetSubjectDN = targetCert.getSubjectName();

        // Verify the subject DN matches the target cert's subject DN.
        // Agent has null subject DN so he can revoke any certificate.
        // Other users can only revoke their own certificate.
        if (subjectDN != null && !subjectDN.equals(targetSubjectDN.toString())) {
            throw new UnauthorizedException(
                    "Certificate 0x" + targetSerialNumber.toString(16) + " belongs to different subject.");
        }

        boolean targetIsCACert = isSystemCertificate(targetCert);

        // If not revoking CA cert verify target cert is not CA cert.
        if (!revokingCACert && targetIsCACert) {
            throw new UnauthorizedException(
                    "Certificate 0x" + targetSerialNumber.toString(16) + " is a CA signing certificate");
        }

        // If revoking CA Cert verify target cert is CA cert.
        if (revokingCACert && !targetIsCACert) {
            throw new UnauthorizedException(
                    "Certificate 0x" + targetSerialNumber.toString(16) + " is not a CA signing certificate");
        }

        // Verify target cert is not already revoked.
        if (targetRecord.getStatus().equals(CertRecord.STATUS_REVOKED)) {
            throw new BadRequestException(
                    CMS.getLogMessage("CA_CERTIFICATE_ALREADY_REVOKED_1", targetSerialNumber.toString(16)));
        }
    }

    public void addCertificateToRevoke(X509CertImpl cert) {
        addCertificate(cert);
        revCertImpls.add(new RevokedCertImpl(cert.getSerialNumber(), new Date(), entryExtn));
    }

    public void addSerialNumberToUnrevoke(BigInteger serialNumber) throws EBaseException {
        CertRecord record = getCertificateRecord(serialNumber);
        X509CertImpl cert = record.getCertificate();
        addCertificate(cert);
    }

    public CertRecord[] getCertificateRecords(BigInteger[] serialNumbers) throws EBaseException {
        CertRecord[] records = new CertRecord[serialNumbers.length];
        for (int i=0; i<serialNumbers.length; i++) {
            records[i] = getCertificateRecord(serialNumbers[i]);
        }
        return records;
    }

    public CertRecord getCertificateRecord(CertId id) throws EBaseException {
        return getCertificateRecord(id.toBigInteger());
    }

    public CertRecord getCertificateRecord(BigInteger serialNumber) throws EBaseException {
        return repo.readCertificateRecord(serialNumber);
    }

    public X509CertImpl[] getCertificates(CertRecord[] records) throws EBaseException {
        X509CertImpl[] certs = new X509CertImpl[records.length];
        for (int i=0; i<records.length; i++) {
            certs[i] = records[i].getCertificate();
        }
        return certs;
    }

    public void createCRLExtension() throws IOException {

        // Construct a CRL extension for this request.
        entryExtn = new CRLExtensions();

        // Construct a CRL reason code extension.
        CRLReasonExtension crlReasonExtn = new CRLReasonExtension(revocationReason);
        entryExtn.set(crlReasonExtn.getName(), crlReasonExtn);

        // Construct a CRL invalidity date extension.
        if (invalidityDate != null) {
            InvalidityDateExtension invalidityDateExtn = new InvalidityDateExtension(invalidityDate);
            entryExtn.set(invalidityDateExtn.getName(), invalidityDateExtn);
        }
    }

    public void createRevocationRequest() throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        request = requestRepository.createRequest(Request.REVOCATION_REQUEST);

        request.setExtData(Request.REQ_TYPE, Request.REVOCATION_REQUEST);

        request.setExtData(Request.OLD_CERTS, certificates.toArray(new X509CertImpl[certificates.size()]));
        request.setExtData(Request.CERT_INFO, revCertImpls.toArray(new RevokedCertImpl[revCertImpls.size()]));

        if (AuditFormat.FROMUSER.equals(initiative)) {
            request.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_EE);
        } else {
            request.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_AGENT);
        }

        if (comments != null) {
            request.setExtData(Request.REQUESTOR_COMMENTS, comments);
        }

        request.setExtData(Request.REVOKED_REASON, revocationReason.getCode());
    }

    public void processRevocationRequest() throws EBaseException {

        logger.info("RevocationProcessor: Processing revocation request " + request.getRequestId().toHexString());
        logger.debug("RevocationProcessor: - initiative: " + initiative);
        logger.debug("RevocationProcessor: - reason: " + revocationReason);

        logger.debug("RevocationProcessor: - certs:");
        for (X509CertImpl cert : certificates) {
            logger.debug("RevocationProcessor:   - serial number: " + cert.getSerialNumber().toString(16));
            logger.debug("RevocationProcessor:   - subject: " + cert.getSubjectName());
        }

        requestQueue.processRequest(request);

        requestStatus = request.getRequestStatus();
        logger.debug("RevocationProcessor: - status: " + requestStatus);

        String type = request.getRequestType();
        logger.debug("RevocationProcessor: - type: " + type);

        // The SVC_PENDING check has been added for the Cloned CA request
        // that is meant for the Master CA. From Clone's point of view
        // the request is complete

        if (requestStatus == RequestStatus.COMPLETE
                || requestStatus == RequestStatus.SVC_PENDING
                    && type.equals(Request.CLA_CERT4CRL_REQUEST)) {

            // audit log the error
            Integer result = request.getExtDataInInteger(Request.RESULT);

            if (result.equals(Request.RES_ERROR)) {
                String[] svcErrors = request.getExtDataInStringArray(Request.SVCERRORS);

                if (svcErrors != null) {
                    for (String err : svcErrors) {
                        logger.debug("RevocationProcessor: - error: " + err);
                        //cmsReq.setErrorDescription(err);
                    }
                }

                throw new EBaseException(CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED"));
            }

            long endTime = new Date().getTime();
            logger.debug("RevocationProcessor: - time: " + (endTime - startTime));
        }
    }

    public void createUnrevocationRequest() throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        request = requestRepository.createRequest(Request.UNREVOCATION_REQUEST);

        request.setExtData(Request.REQ_TYPE, Request.UNREVOCATION_REQUEST);

        Collection<BigInteger> serialNumbers = new ArrayList<>();
        for (X509CertImpl cert : certificates) {
            serialNumbers.add(cert.getSerialNumber());
        }
        request.setExtData(Request.OLD_SERIALS, serialNumbers.toArray(new BigInteger[serialNumbers.size()]));
        request.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_AGENT);
    }

    public void processUnrevocationRequest() throws EBaseException {

        logger.info("RevocationProcessor: Processing unrevocation request " + request.getRequestId().toHexString());
        logger.debug("RevocationProcessor: - initiative: " + initiative);

        logger.debug("RevocationProcessor: - certs:");
        for (X509CertImpl cert : certificates) {
            logger.debug("RevocationProcessor:   - serial number: " + cert.getSerialNumber().toString(16));
            logger.debug("RevocationProcessor:   - subject: " + cert.getSubjectName());
        }

        requestQueue.processRequest(request);

        requestStatus = request.getRequestStatus();
        logger.debug("RevocationProcessor: - status: " + requestStatus);

        String type = request.getRequestType();
        logger.debug("RevocationProcessor: - type: " + type);

        if (requestStatus == RequestStatus.COMPLETE
                || requestStatus == RequestStatus.SVC_PENDING && type.equals(Request.CLA_UNCERT4CRL_REQUEST)) {

            Integer result = request.getExtDataInInteger(Request.RESULT);

            if (result.equals(Request.RES_ERROR)) {
                String error = request.getExtDataInString(Request.ERROR);
                logger.debug("RevocationProcessor: - error: " + error);
            }
        }
    }

    /**
     * A system certificate such as the CA signing certificate
     * should not be allowed to delete.
     * The main purpose is to avoid revoking the self signed
     * CA certificate accidentally.
     */
    public boolean isSystemCertificate(X509Certificate cert) throws EBaseException {

        X509Certificate caCert = authority.getCACert();
        if (caCert == null)
            return false;

        // check whether it's a CA certificate
        if (!caCert.getSerialNumber().equals(cert.getSerialNumber()))
            return false;

        // check whether it's a self-signed we certificate
        return caCert.getSubjectDN().equals(caCert.getIssuerDN());
    }

    public void auditChangeRequest(String status) {

        Auditor auditor = engine.getAuditor();
        if (auditor == null)
            return;

        signedAuditLogger.log(new CertStatusChangeRequestEvent(
                auditor.getSubjectID(),
                status,
                request,
                serialNumber == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : serialNumber.toHexString(),
                requestType));
    }

    public void auditChangeRequestProcessed(String status) {

        Auditor auditor = engine.getAuditor();
        if (auditor == null)
            return;

        // store a message in the signed audit log file
        // if and only if "requestStatus" is
        // "complete", "revoked", or "canceled"

        if (!(requestStatus == RequestStatus.COMPLETE
                || requestStatus == RequestStatus.REJECTED
                || requestStatus == RequestStatus.CANCELED)) return;

        signedAuditLogger.log(new CertStatusChangeRequestProcessedEvent(
                auditor.getSubjectID(),
                status,
                request,
                serialNumber == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : serialNumber.toHexString(),
                requestType,
                String.valueOf(revocationReason.getCode()),
                requestStatus));
    }
}
