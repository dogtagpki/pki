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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import netscape.security.x509.RevocationReason;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.BadRequestException;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.base.UnauthorizedException;
import com.netscape.cms.servlet.cert.model.CertDAO;
import com.netscape.cms.servlet.cert.model.CertRevokeRequest;
import com.netscape.cms.servlet.cert.model.CertUnrevokeRequest;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.processors.Processor;
import com.netscape.cms.servlet.request.model.CertRequestDAO;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.CertRetrievalRequestData;

/**
 * @author alee
 *
 */
public class CertResourceService extends CMSResourceService implements CertResource {

    ICertificateAuthority authority;

    public CertResourceService() {
        authority = (ICertificateAuthority) CMS.getSubsystem("ca");
    }

    public CertDAO createDAO() {
        CertDAO dao = new CertDAO();
        dao.setLocale(getLocale());
        dao.setUriInfo(uriInfo);
        return dao;
    }

    private void validateRequest(CertId id) {

        if (id == null) {
            throw new BadRequestException("Invalid id in CertResourceService.validateRequest.");
        }

    }

    @Override
    public CertificateData getCert(CertId id) {

        validateRequest(id);

        CertRetrievalRequestData data = new CertRetrievalRequestData();
        data.setCertId(id);
        CertDAO dao = createDAO();

        CertificateData certData = null;

        try {
            certData = dao.getCert(data);
        } catch (EDBRecordNotFoundException e) {
            throw new CertNotFoundException(id);
        } catch (EBaseException e) {
            throw new CMSException("Problem returning certificate: " + id);
        } catch (CertificateEncodingException e) {
            throw new CMSException("Problem encoding certificate searched for: " + id);
        }

        return certData;

    }

    @Override
    public CertRequestInfo revokeCACert(CertId id, CertRevokeRequest request) {
        return revokeCert(id, request, true);
    }

    @Override
    public CertRequestInfo revokeCert(CertId id, CertRevokeRequest request) {
        return revokeCert(id, request, false);
    }

    public CertRequestInfo revokeCert(CertId id, CertRevokeRequest request, boolean caCert) {

        RevocationReason revReason = request.getReason();
        if (revReason == RevocationReason.REMOVE_FROM_CRL) {
            CertUnrevokeRequest unrevRequest = new CertUnrevokeRequest();
            unrevRequest.setRequestID(request.getRequestID());
            return unrevokeCert(id, unrevRequest);
        }

        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoRevoke-agent", getLocale());
            processor.setStartTime(CMS.getCurrentDate().getTime());

            // TODO: set initiative based on auth info
            processor.setInitiative(AuditFormat.FROMAGENT);

            processor.setSerialNumber(id);
            processor.setRequestID(request.getRequestID());

            processor.setRevocationReason(revReason);
            processor.setRequestType(revReason == RevocationReason.CERTIFICATE_HOLD
                    ? RevocationProcessor.ON_HOLD : RevocationProcessor.REVOKE);
            processor.setInvalidityDate(request.getInvalidityDate());
            processor.setComments(request.getComments());

            processor.setAuthority(authority);

        } catch (EBaseException e) {
            throw new CMSException(e.getMessage());
        }

        try {
            X509Certificate clientCert = null;
            try {
                clientCert = Processor.getSSLClientCertificate(servletRequest);
            } catch (EBaseException e) {
                // No client certificate, ignore.
            }

            ICertRecord clientRecord = null;
            BigInteger clientSerialNumber = null;
            String clientSubjectDN = null;

            if (clientCert != null) {
                clientSerialNumber = clientCert.getSerialNumber();
                clientSubjectDN = clientCert.getSubjectDN().toString();
                clientRecord = processor.getCertificateRecord(clientSerialNumber);

                // Verify client cert is not revoked.
                // TODO: This should be checked during authentication.
                if (clientRecord.getStatus().equals(ICertRecord.STATUS_REVOKED)) {
                    throw new UnauthorizedException(CMS.getLogMessage("CMSGW_UNAUTHORIZED"));
                }
            }

            // Find target cert record if different from client cert.
            ICertRecord targetRecord = id.equals(clientSerialNumber) ? clientRecord : processor.getCertificateRecord(id);
            X509CertImpl targetCert = targetRecord.getCertificate();

            processor.createCRLExtension();
            processor.validateCertificateToRevoke(clientSubjectDN, targetRecord, caCert);
            processor.addCertificateToRevoke(targetCert);
            processor.createRevocationRequest();

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (CMSException e) {
            processor.log(ILogger.LL_FAILURE, e.getMessage());
            processor.auditChangeRequest(ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequest(ILogger.FAILURE);

            throw new CMSException(e.getMessage());

        } catch (IOException e) {
            processor.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED_1", e.toString()));
            processor.auditChangeRequest(ILogger.FAILURE);

            throw new CMSException(CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED"));
        }

        // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
        // to distinguish which type of signed audit log message to save
        // as a failure outcome in case an exception occurs

        try {
            processor.processRevocationRequest();

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);

            throw new CMSException(e.getMessage());
        }

        try {
            IRequest certRequest = processor.getRequest();
            CertRequestDAO dao = new CertRequestDAO();
            return dao.getRequest(certRequest.getRequestId(), uriInfo);

        } catch (EBaseException e) {
            throw new CMSException(e.getMessage());
        }
    }

    @Override
    public CertRequestInfo unrevokeCert(CertId id, CertUnrevokeRequest request) {

        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoUnrevoke", getLocale());

            // TODO: set initiative based on auth info
            processor.setInitiative(AuditFormat.FROMAGENT);

            processor.setSerialNumber(id);
            processor.setRequestID(request.getRequestID());
            processor.setRevocationReason(RevocationReason.CERTIFICATE_HOLD);
            processor.setAuthority(authority);

        } catch (EBaseException e) {
            throw new CMSException(e.getMessage());
        }

        try {
            processor.addSerialNumberToUnrevoke(id.toBigInteger());
            processor.createUnrevocationRequest();

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequest(ILogger.FAILURE);

            throw new CMSException(e.getMessage());
        }

        // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
        // to distinguish which type of signed audit log message to save
        // as a failure outcome in case an exception occurs

        try {
            processor.processUnrevocationRequest();

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);

            throw new CMSException(e.getMessage());
        }

        try {
            IRequest certRequest = processor.getRequest();
            CertRequestDAO dao = new CertRequestDAO();
            return dao.getRequest(certRequest.getRequestId(), uriInfo);

        } catch (EBaseException e) {
            throw new CMSException(e.getMessage());
        }
    }
}
