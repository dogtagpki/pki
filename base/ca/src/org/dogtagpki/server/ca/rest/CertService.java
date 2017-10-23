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

package org.dogtagpki.server.ca.rest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.provider.RSAPublicKey;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509ExtensionException;
import netscape.security.x509.X509Key;

import org.apache.catalina.realm.GenericPrincipal;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertResource;
import com.netscape.certsrv.cert.CertRetrievalRequest;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.dbs.certdb.IRevocationInfo;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.cert.CertRequestDAO;
import com.netscape.cms.servlet.cert.FilterBuilder;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class CertService extends PKIService implements CertResource {

    ICertificateAuthority authority;
    ICertificateRepository repo;
    SecureRandom random;

    public static final int DEFAULT_MAXTIME = 0;
    public static final int DEFAULT_MAXRESULTS = 20;

    public CertService() {
        authority = (ICertificateAuthority) CMS.getSubsystem("ca");
        if (authority.noncesEnabled()) {
            JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
            random = jssSubsystem.getRandomNumberGenerator();
        }
        repo = authority.getCertificateRepository();
    }

    @Override
    public Response getCert(CertId id) {
        return createOKResponse(getCertData(id));
    }

    @Override
    public Response reviewCert(CertId id) {
        return createOKResponse(getCertData(id, true));
    }

    public CertData getCertData(CertId id) {
        return getCertData(id, false);
    }

    public CertData getCertData(CertId id, boolean generateNonce) {
        if (id == null) {
            throw new BadRequestException("Unable to get certificate: Invalid id.");
        }

        CertRetrievalRequest data = new CertRetrievalRequest(id);

        CertData certData = null;

        try {
            certData = getCert(data, generateNonce);
        } catch (EDBRecordNotFoundException e) {
            throw new CertNotFoundException(id);
        } catch (EBaseException e) {
            throw new PKIException(e.getMessage(), e);
        } catch (CertificateEncodingException e) {
            throw new PKIException(e.getMessage(), e);
        }

        return certData;
    }

    @Override
    public Response revokeCACert(CertId id, CertRevokeRequest request) {
        return revokeCert(id, request, true);
    }

    @Override
    public Response revokeCert(CertId id, CertRevokeRequest request) {
        return revokeCert(id, request, false);
    }

    public Response revokeCert(CertId id, CertRevokeRequest request, boolean caCert) {
        if (id == null) {
            CMS.debug("revokeCert: id is null");
            throw new BadRequestException("Unable to revoke cert: invalid id");
        }
        if (request == null) {
            CMS.debug("revokeCert: request is null");
            throw new BadRequestException("Unable to revoke cert: invalid request");
        }

        // check cert actually exists.  This will throw a CertNotFoundException
        // if the cert does not exist
        @SuppressWarnings("unused")
        CertData data = getCertData(id);

        RevocationReason revReason = request.getReason();
        if (revReason == RevocationReason.REMOVE_FROM_CRL) {
            return unrevokeCert(id);
        }

        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoRevoke-agent", getLocale(headers));
            processor.setStartTime(CMS.getCurrentDate().getTime());

            // TODO: set initiative based on auth info
            processor.setInitiative(AuditFormat.FROMAGENT);

            processor.setSerialNumber(id);

            processor.setRevocationReason(revReason);
            processor.setRequestType(revReason == RevocationReason.CERTIFICATE_HOLD
                    ? RevocationProcessor.ON_HOLD : RevocationProcessor.REVOKE);
            processor.setInvalidityDate(request.getInvalidityDate());
            processor.setComments(request.getComments());

            processor.setAuthority(authority);

        } catch (EBaseException e) {
            throw new PKIException(e.getMessage());
        }

        try {
            X509Certificate clientCert = null;
            try {
                clientCert = CAProcessor.getSSLClientCertificate(servletRequest);
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

            if (authority.noncesEnabled() &&
                !processor.isMemberOfSubsystemGroup(clientCert)) {
                processor.validateNonce(servletRequest, "cert-revoke", id.toBigInteger(), request.getNonce());

            }

            // Find target cert record if different from client cert.
            ICertRecord targetRecord = id.equals(clientSerialNumber) ? clientRecord : processor.getCertificateRecord(id);
            X509CertImpl targetCert = targetRecord.getCertificate();

            processor.createCRLExtension();

            // TODO remove hardcoded role names and consult authzmgr
            // (so that we can handle externally-authenticated principals)
            GenericPrincipal principal =
                (GenericPrincipal) servletRequest.getUserPrincipal();
            String subjectDN = principal.hasRole("Certificate Manager Agents") ?
                    null : clientSubjectDN;

            processor.validateCertificateToRevoke(subjectDN, targetRecord, caCert);
            processor.addCertificateToRevoke(targetCert);
            processor.createRevocationRequest();

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (PKIException e) {
            processor.log(ILogger.LL_FAILURE, e.getMessage());
            processor.auditChangeRequest(ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequest(ILogger.FAILURE);

            throw new PKIException(e.getMessage());

        } catch (IOException e) {
            processor.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED_1", e.toString()));
            processor.auditChangeRequest(ILogger.FAILURE);

            throw new PKIException(CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED"));
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

            throw new PKIException(e.getMessage());
        }

        try {
            IRequest certRequest = processor.getRequest();
            CertRequestDAO dao = new CertRequestDAO();
            return createOKResponse(dao.getRequest(certRequest.getRequestId(), uriInfo));

        } catch (EBaseException e) {
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response unrevokeCert(CertId id) {
        if (id == null) {
            CMS.debug("unrevokeCert: id is null");
            throw new BadRequestException("Unable to unrevoke cert: invalid id");
        }
        if (request == null) {
            CMS.debug("unrevokeCert: request is null");
            throw new BadRequestException("Unable to unrevoke cert: invalid request");
        }

        // check cert actually exists.  This will throw a CertNotFoundException
        // if the cert does not exist
        @SuppressWarnings("unused")
        CertData data = getCertData(id);

        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoUnrevoke", getLocale(headers));

            // TODO: set initiative based on auth info
            processor.setInitiative(AuditFormat.FROMAGENT);

            processor.setSerialNumber(id);
            processor.setRevocationReason(RevocationReason.CERTIFICATE_HOLD);
            processor.setAuthority(authority);

        } catch (EBaseException e) {
            throw new PKIException(e.getMessage());
        }

        try {
            processor.addSerialNumberToUnrevoke(id.toBigInteger());
            processor.createUnrevocationRequest();

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequest(ILogger.FAILURE);

            throw new PKIException(e.getMessage());
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

            throw new PKIException(e.getMessage());
        }

        try {
            IRequest certRequest = processor.getRequest();
            CertRequestDAO dao = new CertRequestDAO();
            return createOKResponse(dao.getRequest(certRequest.getRequestId(), uriInfo));

        } catch (EBaseException e) {
            throw new PKIException(e.getMessage());
        }
    }

    private String createSearchFilter(String status) {
        String filter;

        if (status == null) {
            filter = "(certstatus=*)"; // allCerts VLV

        } else  {
            filter = "(certStatus=" + LDAPUtil.escapeFilter(status) + ")";
        }

        return filter;
    }

    private String createSearchFilter(CertSearchRequest data) {
        if (data == null) {
            return null;
        }
        FilterBuilder builder = new FilterBuilder(data);
        return builder.buildFilter();
    }

    @Override
    public Response listCerts(String status, Integer maxResults, Integer maxTime, Integer start, Integer size) {

        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime    = maxTime == null ? DEFAULT_MAXTIME : maxTime;
        start      = start == null ? 0 : start;
        size       = size == null ? DEFAULT_SIZE : size;

        String filter = createSearchFilter(status);
        CMS.debug("CertService.listCerts: filter: " + filter);

        CertDataInfos infos = new CertDataInfos();
        try {
            Enumeration<ICertRecord> e = repo.searchCertificates(filter, maxResults, maxTime);
            if (e == null) {
                throw new EBaseException("search results are null");
            }

            // store non-null results in a list
            List<CertDataInfo> results = new ArrayList<CertDataInfo>();
            while (e.hasMoreElements()) {
                ICertRecord rec = e.nextElement();
                if (rec == null) continue;
                results.add(createCertDataInfo(rec));
            }

            int total = results.size();
            infos.setTotal(total);

            // return entries in the requested page
            for (int i = start; i < start + size && i < total ; i++) {
                infos.addEntry(results.get(i));
            }

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start - size, 0)).build();
                infos.addLink(new Link("prev", uri));
            }

            if (start + size < total) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start + size).build();
                infos.addLink(new Link("next", uri));
            }

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Error listing certs in CertService.listCerts!", e);
        }

        return createOKResponse(infos);
    }

    @Override
    public Response searchCerts(CertSearchRequest data, Integer start, Integer size) {

        CMS.debug("CertService.searchCerts()");

        if (data == null) {
            throw new BadRequestException("Search request is null");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        String filter = createSearchFilter(data);
        CMS.debug("CertService: filter: " + filter);

        CertDataInfos infos = new CertDataInfos();
        try {
            ICertRecordList list = repo.findCertRecordsInList(filter, null, "serialno", size);
            int total = list.getSize();
            CMS.debug("CertService: total: " + total);

            // return entries in the requested page
            for (int i = start; i < start + size && i < total; i++) {
                ICertRecord record = list.getCertRecord(i);

                if (record == null) {
                    CMS.debug("CertService: Certificate record not found");
                    throw new PKIException("Certificate record not found");
                }

                infos.addEntry(createCertDataInfo(record));
            }

            infos.setTotal(total);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start - size, 0)).build();
                infos.addLink(new Link("prev", uri));
            }

            if (start + size < total) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start + size).build();
                infos.addLink(new Link("next", uri));
            }

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Unable to search certificates: " + e, e);
        }

        return createOKResponse(infos);
    }

    public CertData getCert(CertRetrievalRequest data, boolean generateNonce) throws EBaseException, CertificateEncodingException {
        CertId certId = data.getCertId();

        //find the cert in question
        ICertRecord record = repo.readCertificateRecord(certId.toBigInteger());
        X509CertImpl cert = record.getCertificate();

        CertData certData = new CertData();

        certData.setSerialNumber(certId);

        Principal issuerDN = cert.getIssuerDN();
        if (issuerDN != null) certData.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN != null) certData.setSubjectDN(subjectDN.toString());

        String base64 = CMS.getEncodedCert(cert);
        certData.setEncoded(base64);

        ICertPrettyPrint print = CMS.getCertPrettyPrint(cert);
        certData.setPrettyPrint(print.toString(getLocale(headers)));

        String p7Str = getCertChainData(cert);
        certData.setPkcs7CertChain(p7Str);

        Date notBefore = cert.getNotBefore();
        if (notBefore != null) certData.setNotBefore(notBefore.toString());

        Date notAfter = cert.getNotAfter();
        if (notAfter != null) certData.setNotAfter(notAfter.toString());

        certData.setRevokedOn(record.getRevokedOn());
        certData.setRevokedBy(record.getRevokedBy());

        IRevocationInfo revInfo = record.getRevocationInfo();
        if (revInfo != null) {
            CRLExtensions revExts = revInfo.getCRLEntryExtensions();
            if (revExts != null) {
                try {
                    CRLReasonExtension ext = (CRLReasonExtension)
                        revExts.get(CRLReasonExtension.NAME);
                    certData.setRevocationReason(ext.getReason().getCode());
                } catch (X509ExtensionException e) {
                    // nothing to do
                }
            }
        }

        certData.setStatus(record.getStatus());

        if (authority.noncesEnabled() && generateNonce) {
            // generate nonce
            long n = random.nextLong();
            // store nonce in session
            Map<Object, Long> nonces = authority.getNonces(servletRequest, "cert-revoke");
            nonces.put(certId.toBigInteger(), n);
            // return nonce to client
            certData.setNonce(n);
        }

        URI uri = uriInfo.getBaseUriBuilder().path(CertResource.class, "getCert").build(certId.toHexString());
        certData.setLink(new Link("self", uri));

        return certData;
    }

    private CertDataInfo createCertDataInfo(ICertRecord record) throws EBaseException, InvalidKeyException {
        CertDataInfo info = new CertDataInfo();

        CertId id = new CertId(record.getSerialNumber());
        info.setID(id);

        X509Certificate cert = record.getCertificate();
        info.setIssuerDN(cert.getIssuerDN().toString());
        info.setSubjectDN(cert.getSubjectDN().toString());
        info.setStatus(record.getStatus());
        info.setVersion(cert.getVersion());
        info.setType(cert.getType());

        PublicKey key = cert.getPublicKey();
        if (key instanceof X509Key) {
            X509Key x509Key = (X509Key)key;
            info.setKeyAlgorithmOID(x509Key.getAlgorithmId().getOID().toString());

            if (x509Key.getAlgorithmId().toString().equalsIgnoreCase("RSA")) {
                RSAPublicKey rsaKey = new RSAPublicKey(x509Key.getEncoded());
                info.setKeyLength(rsaKey.getKeySize());
            }
        }

        info.setNotValidBefore(cert.getNotBefore());
        info.setNotValidAfter(cert.getNotAfter());

        info.setIssuedOn(record.getCreateTime());
        info.setIssuedBy(record.getIssuedBy());

        info.setRevokedOn(record.getRevokedOn());
        info.setRevokedBy(record.getRevokedBy());

        URI uri = uriInfo.getBaseUriBuilder().path(CertResource.class, "getCert").build(id.toHexString());
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

            p7Str = Utils.base64encode(p7Bytes, true);
        } catch (Exception e) {
            p7Str = null;
        }

        return p7Str;
    }
}
