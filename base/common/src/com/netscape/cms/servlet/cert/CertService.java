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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.X509CertImpl;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.BadRequestException;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.base.UnauthorizedException;
import com.netscape.cms.servlet.cert.model.CertDataInfo;
import com.netscape.cms.servlet.cert.model.CertDataInfos;
import com.netscape.cms.servlet.cert.model.CertRevokeRequest;
import com.netscape.cms.servlet.cert.model.CertSearchData;
import com.netscape.cms.servlet.cert.model.CertUnrevokeRequest;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.processors.Processor;
import com.netscape.cms.servlet.request.model.CertRequestDAO;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.CertRetrievalRequestData;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class CertService extends PKIService implements CertResource {

    ICertificateAuthority authority;
    ICertificateRepository repo;

    public final static int DEFAULT_SIZE = 20;

    public CertService() {
        authority = (ICertificateAuthority) CMS.getSubsystem("ca");
        repo = authority.getCertificateRepository();
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

        CertificateData certData = null;

        try {
            certData = getCert(data);
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

    private String createSearchFilter(String status) {
        String filter = "";

        if ((status == null)) {
            filter = "(serialno=*)";
            return filter;
        }

        if (status != null) {
            filter += "(certStatus=" + LDAPUtil.escapeFilter(status) + ")";
        }

        return filter;
    }

    private String createSearchFilter(CertSearchData data) {
        if (data == null) {
            return null;
        }

        return data.buildFilter();
    }

    @Override
    public CertDataInfos listCerts(String status, int maxResults, int maxTime) {
        // get ldap filter
        String filter = createSearchFilter(status);
        CMS.debug("listKeys: filter is " + filter);

        CertDataInfos infos;
        try {
            infos = getCertList(filter, maxResults, maxTime);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new CMSException("Error listing certs in CertsResourceService.listCerts!");
        }
        return infos;
    }

    @Override
    public CertDataInfos searchCerts(CertSearchData data, Integer start, Integer size) {
        if (data == null) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;
        String filter = createSearchFilter(data);

        CertDataInfos infos = new CertDataInfos();

        Enumeration<ICertRecord> e = null;
        try {

            e = repo.findCertRecords(filter);

            int i = 0;

            // skip to the start of the page
            for (; i < start && e.hasMoreElements(); i++)
                e.nextElement();

            // return entries up to the page size
            for (; i < start + size && e.hasMoreElements(); i++) {
                ICertRecord user = e.nextElement();
                infos.addCertData(createCertDataInfo(user));
            }

            // count the total entries
            for (; e.hasMoreElements(); i++)
                e.nextElement();

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start - size, 0)).build();
                infos.addLink(new Link("prev", uri));
            }

            if (start + size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start + size).build();
                infos.addLink(new Link("next", uri));
            }
        } catch (EBaseException e1) {
            throw new CMSException("Error listing certs in CertsResourceService.listCerts!" + e.toString());
        }

        return infos;
    }

    /**
     * Returns list of certs meeting specified search filter.
     * Currently, vlv searches are not used for certs.
     *
     * @param filter
     * @param maxResults
     * @param maxTime
     * @param uriInfo
     * @return
     * @throws EBaseException
     */
    private CertDataInfos getCertList(String filter, int maxResults, int maxTime)
            throws EBaseException {
        List<CertDataInfo> list = new ArrayList<CertDataInfo>();
        Enumeration<ICertRecord> e = null;

        e = repo.searchCertificates(filter, maxResults, maxTime);
        if (e == null) {
            throw new EBaseException("search results are null");
        }

        while (e.hasMoreElements()) {
            ICertRecord rec = e.nextElement();
            if (rec != null) {
                list.add(createCertDataInfo(rec));
            }
        }

        CertDataInfos ret = new CertDataInfos();
        ret.setCertInfos(list);

        return ret;
    }

    public CertificateData getCert(CertRetrievalRequestData data) throws EBaseException, CertificateEncodingException {
        CertId certId = data.getCertId();

        //find the cert in question
        ICertRecord record = repo.readCertificateRecord(certId.toBigInteger());
        X509CertImpl cert = record.getCertificate();

        CertificateData certData = new CertificateData();

        certData.setSerialNumber(certId);

        Principal issuerDN = cert.getIssuerDN();
        if (issuerDN != null) certData.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN != null) certData.setSubjectDN(subjectDN.toString());

        String base64 = CMS.getEncodedCert(cert);
        certData.setEncoded(base64);

        ICertPrettyPrint print = CMS.getCertPrettyPrint(cert);
        certData.setPrettyPrint(print.toString(getLocale()));

        String p7Str = getCertChainData(cert);
        certData.setPkcs7CertChain(p7Str);

        Date notBefore = cert.getNotBefore();
        if (notBefore != null) certData.setNotBefore(notBefore.toString());

        Date notAfter = cert.getNotAfter();
        if (notAfter != null) certData.setNotAfter(notAfter.toString());

        certData.setStatus(record.getStatus());

        URI uri = uriInfo.getBaseUriBuilder().path(CertResource.class).path("{id}").build(certId.toHexString());
        certData.setLink(new Link("self", uri));

        return certData;
    }

    private CertDataInfo createCertDataInfo(ICertRecord record) throws EBaseException {
        CertDataInfo info = new CertDataInfo();

        CertId id = new CertId(record.getSerialNumber());
        info.setID(id);

        X509Certificate cert = record.getCertificate();
        info.setSubjectDN(cert.getSubjectDN().toString());

        info.setStatus(record.getStatus());

        URI uri = uriInfo.getBaseUriBuilder().path(CertResource.class).path("{id}").build(id.toHexString());
        info.setLink(new Link("self", uri));

        return info;
    }

    private String getCertChainData(X509CertImpl x509cert) {
        X509Certificate mCACerts[];

        if (x509cert == null) {
            return null;
        }

        try {
            mCACerts = authority.getCACertChain().getChain();
        } catch (Exception e) {
            mCACerts = null;
        }

        X509CertImpl[] certsInChain = new X509CertImpl[1];

        int mCACertsLength = 0;
        boolean certAlreadyInChain = false;
        int certsInChainLength = 0;
        if (mCACerts != null) {
            mCACertsLength = mCACerts.length;
            for (int i = 0; i < mCACertsLength; i++) {
                if (x509cert.equals(mCACerts[i])) {
                    certAlreadyInChain = true;
                    break;
                }
            }

            if (certAlreadyInChain == true) {
                certsInChainLength = mCACertsLength;
            } else {
                certsInChainLength = mCACertsLength + 1;
            }

            certsInChain = new X509CertImpl[certsInChainLength];

        }

        certsInChain[0] = x509cert;

        if (mCACerts != null) {
            int curCount = 1;
            for (int i = 0; i < mCACertsLength; i++) {
                if (!x509cert.equals(mCACerts[i])) {
                    certsInChain[curCount] = (X509CertImpl) mCACerts[i];
                    curCount++;
                }

            }
        }

        String p7Str;

        try {
            PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                    new ContentInfo(new byte[0]),
                    certsInChain,
                    new SignerInfo[0]);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            p7.encodeSignedData(bos, false);
            byte[] p7Bytes = bos.toByteArray();

            p7Str = Utils.base64encode(p7Bytes);
        } catch (Exception e) {
            p7Str = null;
        }

        return p7Str;
    }
}
