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
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtag.util.cert.CertUtil;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.provider.RSAPublicKey;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertResource;
import com.netscape.certsrv.cert.CertRetrievalRequest;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.cert.FilterBuilder;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.cert.CertPrettyPrint;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertRecordList;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 *
 */
public class CertService extends PKIService implements CertResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertService.class);

    CertificateAuthority authority;
    CertificateRepository repo;
    SecureRandom random;

    public static final int DEFAULT_MAXTIME = 0;
    public static final int DEFAULT_MAXRESULTS = 20;

    public CertService() {

        CAEngine engine = CAEngine.getInstance();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        authority = engine.getCA();

        if (engine.getEnableNonces()) {
            random = jssSubsystem.getRandomNumberGenerator();
        }

        repo = engine.getCertificateRepository();
    }

    @Override
    public Response getCert(CertId id) {
        logger.info("Getting certificate " + id.toHexString());
        return createOKResponse(getCertData(id));
    }

    @Override
    public Response reviewCert(CertId id) {
        logger.info("Reviewing certificate " + id.toHexString());
        return createOKResponse(getCertData(id, true));
    }

    public CertData getCertData(CertId id) {
        return getCertData(id, false);
    }

    public CertData getCertData(CertId id, boolean generateNonce) {
        if (id == null) {
            throw new BadRequestException("Unable to get certificate: Missing certificate ID");
        }

        CertRetrievalRequest data = new CertRetrievalRequest(id);

        CertData certData = null;

        try {
            certData = getCert(data, generateNonce);

        } catch (EDBRecordNotFoundException e) {
            throw new CertNotFoundException(id);

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }

        return certData;
    }

    @Override
    public Response revokeCACert(CertId id, CertRevokeRequest request) {
        logger.info("Revoking CA certificate " + id.toHexString());
        return revokeCert(id, request, true);
    }

    @Override
    public Response revokeCert(CertId id, CertRevokeRequest request) {
        logger.info("Revoking certificate " + id.toHexString());
        return revokeCert(id, request, false);
    }

    public Response revokeCert(CertId id, CertRevokeRequest request, boolean caCert) {
        if (id == null) {
            logger.warn("Unable to revoke cert: Missing certificate ID");
            throw new BadRequestException("Unable to revoke cert: Missing certificate ID");
        }
        if (request == null) {
            logger.warn("revokeCert: request is null");
            throw new BadRequestException("Unable to revoke cert: invalid request");
        }

        // check cert actually exists.  This will throw a CertNotFoundException
        // if the cert does not exist
        @SuppressWarnings("unused")
        CertData data = getCertData(id);

        RevocationReason revReason = RevocationReason.valueOf(request.getReason());
        if (revReason == RevocationReason.REMOVE_FROM_CRL) {
            return unrevokeCert(id);
        }

        CAEngine engine = CAEngine.getInstance();

        String caIssuerDN = null;
        X500Name caX500DN = null;
        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoRevoke-agent", getLocale(headers));
            processor.setCMSEngine(engine);
            processor.setStartTime(new Date().getTime());

            // TODO: set initiative based on auth info
            processor.setInitiative(AuditFormat.FROMAGENT);

            processor.setSerialNumber(id);

            processor.setRevocationReason(revReason);
            processor.setRequestType(revReason == RevocationReason.CERTIFICATE_HOLD
                    ? RevocationProcessor.ON_HOLD : RevocationProcessor.REVOKE);
            processor.setInvalidityDate(request.getInvalidityDate());
            processor.setComments(request.getComments());

            processor.setAuthority(authority);

            caX500DN = authority.getCACert().getSubjectName();

        } catch (EBaseException e) {
            logger.error("Unable to revoke certificate: " + e.getMessage(), e);
            throw new PKIException("Unable to revoke certificate: " + e.getMessage(), e);
        }

        try {
            X509Certificate clientCert = null;
            try {
                clientCert = CAProcessor.getSSLClientCertificate(servletRequest);
            } catch (EBaseException e) {
                // No client certificate, ignore.
            }

            CertRecord clientRecord = null;
            BigInteger clientSerialNumber = null;
            String clientSubjectDN = null;

            if (clientCert != null) {
                clientSerialNumber = clientCert.getSerialNumber();
                clientSubjectDN = clientCert.getSubjectDN().toString();

                X500Name x500issuerDN = (X500Name) clientCert.getIssuerDN();
                /*
                 * internal revocation check only to be conducted for certs
                 * issued by this CA
                 * For client certs issued by external CAs, TLS mutual auth
                 * would have completed the authenticaton/verification if
                 * OCSP was enabled;
                 * Furthermore, prior to the actual revocation, client cert
                 * is mapped against the agent group database for proper
                 * privilege regardless of the issuer.
                 */
                if (x500issuerDN.equals(caX500DN)) {
                    logger.info("CertService.revokeCert: client cert issued by this CA");
                    clientRecord = processor.getCertificateRecord(clientSerialNumber);

                    // Verify client cert is not revoked.
                    // TODO: This should be checked during authentication.
                    if (clientRecord.getStatus().equals(CertRecord.STATUS_REVOKED)) {
                        throw new UnauthorizedException(CMS.getLogMessage("CMSGW_UNAUTHORIZED"));
                    }
                } else {
                    logger.info("CertService.revokeCert: client cert not issued by this CA");
                    if (engine.getAllowExtCASignedAgentCerts()) {
                        logger.info("CertService.revokeCert: allowExtCASignedAgentCerts true;");
                    } else {
                        logger.error("CertService.revokeCert: allowExtCASignedAgentCerts false;");
                        throw new UnauthorizedException(CMS.getLogMessage("CMSGW_UNAUTHORIZED"));
                    }
                }
            }

            if (engine.getEnableNonces() &&
                !processor.isMemberOfSubsystemGroup(clientCert)) {
                processor.validateNonce(servletRequest, "cert-revoke", id.toBigInteger(), request.getNonce());

            }

            // Find target cert record if different from client cert.
            CertRecord targetRecord = id.equals(clientSerialNumber) ? clientRecord : processor.getCertificateRecord(id);
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
            logger.warn("Unable to pre-process revocation request: " + e.getMessage());
            processor.auditChangeRequest(ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            logger.error("Unable to pre-process revocation request: " + e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);
            throw new PKIException("Unable to revoke cert: " + e.getMessage(), e);

        } catch (IOException e) {
            logger.error("Unable to pre-process revocation request: " + e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);
            throw new PKIException("Unable to revoke cert: " + e.getMessage(), e);
        }

        // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
        // to distinguish which type of signed audit log message to save
        // as a failure outcome in case an exception occurs

        try {
            processor.processRevocationRequest();

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("Unable to process revocation request: " + e.getMessage(), e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);
            throw new PKIException("Unable to revoke certificate: " + e.getMessage(), e);
        }

        try {
            Request certRequest = processor.getRequest();
            CertRequestDAO dao = new CertRequestDAO();
            CertRequestInfo requestInfo = dao.getRequest(certRequest.getRequestId(), uriInfo);
            return createOKResponse(requestInfo);

        } catch (EBaseException e) {
            logger.error("Unable to create revocation response: " + e.getMessage(), e);
            throw new PKIException("Unable to create revocation response: " + e.getMessage(), e);
        }
    }

    @Override
    public Response unrevokeCert(CertId id) {

        if (id == null) {
            logger.warn("Unable to unrevoke certificate: Missing certificate ID");
            throw new BadRequestException("Unable to unrevoke certificate: Missing certificate ID");
        }

        logger.info("Unrevoking certificate " + id.toHexString());

        if (request == null) {
            logger.warn("unrevokeCert: request is null");
            throw new BadRequestException("Unable to unrevoke cert: invalid request");
        }

        // check cert actually exists.  This will throw a CertNotFoundException
        // if the cert does not exist
        @SuppressWarnings("unused")
        CertData data = getCertData(id);

        CAEngine engine = (CAEngine) getCMSEngine();
        RevocationProcessor processor;

        try {
            processor = new RevocationProcessor("caDoUnrevoke", getLocale(headers));
            processor.setCMSEngine(engine);

            // TODO: set initiative based on auth info
            processor.setInitiative(AuditFormat.FROMAGENT);

            processor.setSerialNumber(id);
            processor.setRevocationReason(RevocationReason.CERTIFICATE_HOLD);
            processor.setAuthority(authority);

        } catch (EBaseException e) {
            logger.error("Unable to create revocation processor: " + e.getMessage(), e);
            throw new PKIException("Unable to unrevoke certificate: " + e.getMessage(), e);
        }

        try {
            processor.addSerialNumberToUnrevoke(id.toBigInteger());
            processor.createUnrevocationRequest();

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("Unable to pre-process unrevocation request: " + e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);
            throw new PKIException("Unable to unrevoke certificate: " + e.getMessage(), e);
        }

        // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
        // to distinguish which type of signed audit log message to save
        // as a failure outcome in case an exception occurs

        try {
            processor.processUnrevocationRequest();

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("Unable to process unrevocation request: " + e.getMessage(), e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);
            throw new PKIException("Unable to unrevoke certificate: " + e.getMessage(), e);
        }

        try {
            Request certRequest = processor.getRequest();
            CertRequestDAO dao = new CertRequestDAO();
            return createOKResponse(dao.getRequest(certRequest.getRequestId(), uriInfo));

        } catch (EBaseException e) {
            logger.error("Unable to create unrevocation response: " + e.getMessage(), e);
            throw new PKIException("Unable to create unrevocation response: " + e.getMessage(), e);
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

        logger.info("Listing certificates");

        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime    = maxTime == null ? DEFAULT_MAXTIME : maxTime;
        start      = start == null ? 0 : start;
        size       = size == null ? DEFAULT_SIZE : size;

        String filter = createSearchFilter(status);
        logger.info("Search filter: " + filter);

        CertDataInfos infos = new CertDataInfos();
        try {
            Enumeration<CertRecord> e = repo.searchCertificates(filter, maxResults, maxTime);
            if (e == null) {
                throw new EBaseException("search results are null");
            }

            // store non-null results in a list
            List<CertDataInfo> results = new ArrayList<>();
            while (e.hasMoreElements()) {
                CertRecord rec = e.nextElement();
                if (rec == null) continue;
                results.add(createCertDataInfo(rec));
            }

            int total = results.size();
            logger.info("Search results: " + total);
            infos.setTotal(total);

            // return entries in the requested page
            for (int i = start; i < start + size && i < total ; i++) {
                infos.addEntry(results.get(i));
            }
        } catch (Exception e) {
            logger.error("Unable to list certificates: " + e.getMessage(), e);
            throw new PKIException("Unable to list certificates: " + e.getMessage(), e);
        }

        return createOKResponse(infos);
    }

    @Override
    public Response searchCerts(String searchRequest, Integer start, Integer size) {

        logger.info("Searching for certificates");

        CertSearchRequest data = unmarshall(searchRequest, CertSearchRequest.class);

        if (data == null) {
            throw new BadRequestException("Search request is null");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        String filter = createSearchFilter(data);
        logger.info("Search filter: " + filter);

        CertDataInfos infos = new CertDataInfos();
        try {
            CertRecordList list = repo.findCertRecordsInList(filter, null, "serialno", size);
            int total = list.getSize();
            logger.info("Search results: " + total);

            // return entries in the requested page
            for (int i = start; i < start + size && i < total; i++) {
                CertRecord record = list.getCertRecord(i);

                if (record == null) {
                    logger.warn("Certificate record not found");
                    throw new PKIException("Certificate record not found");
                }

                infos.addEntry(createCertDataInfo(record));
            }

            infos.setTotal(total);
        } catch (Exception e) {
            logger.error("Unable to search for certificates: " + e.getMessage(), e);
            throw new PKIException("Unable to search for certificates: " + e.getMessage(), e);
        }

        return createOKResponse(infos);
    }

    public CertData getCert(CertRetrievalRequest data, boolean generateNonce) throws Exception {

        CAEngine engine = CAEngine.getInstance();

        CertId certId = data.getCertId();

        //find the cert in question
        CertRecord record = repo.readCertificateRecord(certId.toBigInteger());
        X509CertImpl cert = record.getCertificate();

        CertData certData = new CertData();

        certData.setSerialNumber(certId);

        Principal issuerDN = cert.getIssuerName();
        if (issuerDN != null) certData.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectName();
        if (subjectDN != null) certData.setSubjectDN(subjectDN.toString());

        String base64 = CertUtil.toPEM(cert);
        certData.setEncoded(base64);

        CertPrettyPrint print = new CertPrettyPrint(cert);
        certData.setPrettyPrint(print.toString(getLocale(headers)));

        X509Certificate[] certChain = engine.getCertChain(cert);

        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                certChain,
                new SignerInfo[0]);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        pkcs7.encodeSignedData(bos, false);
        byte[] p7Bytes = bos.toByteArray();

        String p7Str = Utils.base64encode(p7Bytes, true);
        certData.setPkcs7CertChain(p7Str);

        Date notBefore = cert.getNotBefore();
        if (notBefore != null) certData.setNotBefore(notBefore.toString());

        Date notAfter = cert.getNotAfter();
        if (notAfter != null) certData.setNotAfter(notAfter.toString());

        certData.setRevokedOn(record.getRevokedOn());
        certData.setRevokedBy(record.getRevokedBy());

        RevocationInfo revInfo = record.getRevocationInfo();
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

        if (engine.getEnableNonces() && generateNonce) {
            // generate nonce
            long n = random.nextLong();
            // store nonce in session
            Map<Object, Long> nonces = engine.getNonces(servletRequest, "cert-revoke");
            nonces.put(certId.toBigInteger(), n);
            // return nonce to client
            certData.setNonce(n);
        }
        return certData;
    }

    private CertDataInfo createCertDataInfo(CertRecord record) throws EBaseException, InvalidKeyException {
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

        return info;
    }
}
