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

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.certsrv.usrgrp.IUser;

/**
 * @author Endi S. Dewata
 */
public class RevocationProcessor extends CertProcessor {

    public final static String REVOKE = "revoke";
    public final static String ON_HOLD = "on-hold";
    public final static String OFF_HOLD = "off-hold";

    public final static String LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_5";
    public final static String LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED_7";

    long startTime;

    ICertificateAuthority authority;
    ICertificateRepository repo;
    IRequestQueue requestQueue;
    IPublisherProcessor publisherProcessor;

    String initiative;
    RequestId requestID;
    CertId serialNumber;
    RevocationReason revocationReason;
    Date invalidityDate;
    String comments;
    String requestType;

    CRLExtensions entryExtn;
    Collection<X509CertImpl> certificates = new ArrayList<X509CertImpl>();
    Collection<RevokedCertImpl> revCertImpls = new ArrayList<RevokedCertImpl>();
    IRequest request;
    RequestStatus requestStatus;

    public RevocationProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    public ICertificateAuthority getAuthority() {
        return authority;
    }

    public void setAuthority(ICertificateAuthority authority) {
        this.authority = authority;
        repo = authority.getCertificateRepository();
        requestQueue = authority.getRequestQueue();
        publisherProcessor = authority.getPublisherProcessor();
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

    public RequestId getRequestID() {
        return requestID;
    }

    public void setRequestID(RequestId requestID) {
        this.requestID = requestID;
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

    public IRequest getRequest() {
        return request;
    }

    public boolean isMemberOfSubsystemGroup(X509Certificate clientCert) {

        if (clientCert == null) {
            return false;
        }

        try {
            X509Certificate certChain[] = new X509Certificate[1];
            certChain[0] = clientCert;

            IUser user = ul.locateUser(new Certificates(certChain));
            return ug.isMemberOf(user, "Subsystem Group");

        } catch (Exception e) {
            CMS.debug("RevocationProcessor:  Failed to map certificate '" +
                    clientCert.getSubjectDN().getName() + "' to user.");
            return false;
        }
    }

    public void validateCertificateToRevoke(String subjectDN, ICertRecord targetRecord, boolean revokingCACert) {

        X509CertImpl targetCert = targetRecord.getCertificate();
        BigInteger targetSerialNumber = targetCert.getSerialNumber();
        Principal targetSubjectDN = targetCert.getSubjectDN();

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
        if (targetRecord.getStatus().equals(ICertRecord.STATUS_REVOKED)) {
            throw new BadRequestException(
                    CMS.getLogMessage("CA_CERTIFICATE_ALREADY_REVOKED_1", targetSerialNumber.toString(16)));
        }
    }

    public void addCertificateToRevoke(X509CertImpl cert) {
        addCertificate(cert);
        revCertImpls.add(new RevokedCertImpl(cert.getSerialNumber(), CMS.getCurrentDate(), entryExtn));
    }

    public void addSerialNumberToUnrevoke(BigInteger serialNumber) throws EBaseException {
        ICertRecord record = getCertificateRecord(serialNumber);
        X509CertImpl cert = record.getCertificate();
        addCertificate(cert);
    }

    public ICertRecord[] getCertificateRecords(BigInteger[] serialNumbers) throws EBaseException {
        ICertRecord[] records = new ICertRecord[serialNumbers.length];
        for (int i=0; i<serialNumbers.length; i++) {
            records[i] = getCertificateRecord(serialNumbers[i]);
        }
        return records;
    }

    public ICertRecord getCertificateRecord(CertId id) throws EBaseException {
        return getCertificateRecord(id.toBigInteger());
    }

    public ICertRecord getCertificateRecord(BigInteger serialNumber) throws EBaseException {
        return repo.readCertificateRecord(serialNumber);
    }

    public X509CertImpl[] getCertificates(ICertRecord[] records) throws EBaseException {
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

        request = requestQueue.newRequest(IRequest.REVOCATION_REQUEST);

        request.setExtData(IRequest.REQ_TYPE, IRequest.REVOCATION_REQUEST);

        request.setExtData(IRequest.OLD_CERTS, certificates.toArray(new X509CertImpl[certificates.size()]));
        request.setExtData(IRequest.CERT_INFO, revCertImpls.toArray(new RevokedCertImpl[revCertImpls.size()]));

        if (AuditFormat.FROMUSER.equals(initiative)) {
            request.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_EE);
        } else {
            request.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_AGENT);
        }

        if (comments != null) {
            request.setExtData(IRequest.REQUESTOR_COMMENTS, comments);
        }

        request.setExtData(IRequest.REVOKED_REASON, revocationReason.toInt());
    }

    public void processRevocationRequest() throws EBaseException {

        requestQueue.processRequest(request);
        requestStatus = request.getRequestStatus();

        CMS.debug("revokeCert: status: " + requestStatus);

        String type = request.getRequestType();

        // The SVC_PENDING check has been added for the Cloned CA request
        // that is meant for the Master CA. From Clone's point of view
        // the request is complete

        if (requestStatus == RequestStatus.COMPLETE
                || requestStatus == RequestStatus.SVC_PENDING
                    && type.equals(IRequest.CLA_CERT4CRL_REQUEST)) {

            // audit log the error
            Integer result = request.getExtDataInInteger(IRequest.RESULT);

            if (result.equals(IRequest.RES_ERROR)) {
                String[] svcErrors = request.getExtDataInStringArray(IRequest.SVCERRORS);

                if (svcErrors != null) {
                    for (String err : svcErrors) {
                        //cmsReq.setErrorDescription(err);
                        for (X509CertImpl cert : certificates) {
                            logRevoke(
                                    request, cert,
                                    "completed with error: " + err,
                                    revocationReason.toString());
                        }
                    }
                }

                throw new EBaseException(CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED"));
            }

            long endTime = CMS.getCurrentDate().getTime();

            // audit log the success.
            for (X509CertImpl cert : certificates) {
                logRevoke(request, cert,
                        "completed",
                        revocationReason + " time: " + (endTime - startTime));
            }

        } else {

            // audit log the pending, revoked and rest
            for (X509CertImpl cert : certificates) {
                logRevoke(request, cert,
                        requestStatus.toString(),
                        revocationReason.toString());
            }
        }
    }

    public void createUnrevocationRequest() throws EBaseException {

        request = requestQueue.newRequest(IRequest.UNREVOCATION_REQUEST);

        request.setExtData(IRequest.REQ_TYPE, IRequest.UNREVOCATION_REQUEST);

        Collection<BigInteger> serialNumbers = new ArrayList<BigInteger>();
        for (X509CertImpl cert : certificates) {
            serialNumbers.add(cert.getSerialNumber());
        }
        request.setExtData(IRequest.OLD_SERIALS, serialNumbers.toArray(new BigInteger[serialNumbers.size()]));
        request.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_AGENT);
    }

    public void processUnrevocationRequest() throws EBaseException {

        requestQueue.processRequest(request);
        requestStatus = request.getRequestStatus();

        String type = request.getRequestType();

        if (requestStatus == RequestStatus.COMPLETE
                || requestStatus == RequestStatus.SVC_PENDING && type.equals(IRequest.CLA_UNCERT4CRL_REQUEST)) {

            Integer result = request.getExtDataInInteger(IRequest.RESULT);

            if (result != null && result.equals(IRequest.RES_SUCCESS)) {
                for (X509CertImpl cert : certificates) {
                    logUnrevoke(request, cert, "completed");
                }

            } else {
                String error = request.getExtDataInString(IRequest.ERROR);
                for (X509CertImpl cert : certificates) {
                    logUnrevoke(request, cert, "completed with error: " + error);
                }
            }

        } else {
            for (X509CertImpl cert : certificates) {
                logUnrevoke(request, cert, requestStatus.toString());
            }
        }
    }

    /**
     * A system certificate such as the CA signing certificate
     * should not be allowed to delete.
     * The main purpose is to avoid revoking the self signed
     * CA certificate accidentally.
     */
    public boolean isSystemCertificate(X509Certificate cert) {

        X509Certificate caCert = authority.getCACert();
        if (caCert == null)
            return false;

        // check whether it's a CA certificate
        if (!caCert.getSerialNumber().equals(cert.getSerialNumber()))
            return false;

        // check whether it's a self-signed we certificate
        return caCert.getSubjectDN().equals(caCert.getIssuerDN());
    }

    public void logRevoke(IRequest revocationRequest, X509Certificate cert, String status, String message) {

        if (logger == null)
            return;

        logger.log(
                ILogger.EV_AUDIT,
                ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.DOREVOKEFORMAT,
                new Object[] {
                        revocationRequest.getRequestId(),
                        initiative,
                        status,
                        cert.getSubjectDN(),
                        cert.getSerialNumber().toString(16),
                        message
                });
    }

    public void logUnrevoke(IRequest unrevocationRequest, X509Certificate cert, String status) {

        if (logger == null)
            return;

        logger.log(
                ILogger.EV_AUDIT,
                ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.DOUNREVOKEFORMAT,
                new Object[] {
                        unrevocationRequest.getRequestId(),
                        initiative,
                        status,
                        cert.getSubjectDN(),
                        cert.getSerialNumber().toString(16),
                });
    }

    public void auditChangeRequest(String status) {

        if (auditor == null)
            return;

        String auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST,
                auditor.getSubjectID(),
                status,
                requestID == null ? ILogger.UNIDENTIFIED : requestID.toString(),
                serialNumber == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : serialNumber.toHexString(),
                requestType);

        auditor.log(auditMessage);
    }

    public void auditChangeRequestProcessed(String status) {

        if (auditor == null)
            return;

        // store a message in the signed audit log file
        // if and only if "requestStatus" is
        // "complete", "revoked", or "canceled"

        if (!(requestStatus == RequestStatus.COMPLETE
                || requestStatus == RequestStatus.REJECTED
                || requestStatus == RequestStatus.CANCELED)) return;

        String auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED,
                auditor.getSubjectID(),
                status,
                requestID == null ? ILogger.UNIDENTIFIED : requestID.toString(),
                serialNumber == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : serialNumber.toHexString(),
                requestType,
                String.valueOf(revocationReason.toInt()),
                requestStatus == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : requestStatus.toString());

        auditor.log(auditMessage);
    }

    public void log(int level, String message) {
        log(ILogger.S_CA, level, message);
    }
}
