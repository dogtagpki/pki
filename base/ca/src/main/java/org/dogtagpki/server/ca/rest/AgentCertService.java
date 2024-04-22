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
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.cert.AgentCertResource;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRetrievalRequest;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.security.JssSubsystem;

/**
 * @author alee
 */
public class AgentCertService extends PKIService implements AgentCertResource {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AgentCertService.class);

    CertificateAuthority authority;
    CertificateRepository repo;
    SecureRandom random;

    public AgentCertService() {

        CAEngine engine = CAEngine.getInstance();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        authority = engine.getCA();

        if (engine.getEnableNonces()) {
            random = jssSubsystem.getRandomNumberGenerator();
        }

        repo = engine.getCertificateRepository();
    }

    @Override
    public Response reviewCert(CertId id) {
        logger.info("Reviewing certificate " + id.toHexString());
        return createOKResponse(getCertData(id, true));
    }

    CertData getCertData(CertId id) {
        return getCertData(id, false);
    }

    CertData getCertData(CertId id, boolean generateNonce) {
        if (id == null) {
            throw new BadRequestException("Unable to get certificate: Missing certificate ID");
        }

        CertRetrievalRequest data = new CertRetrievalRequest(id);

        CertData certData = null;

        try {
            certData = getCert(data, generateNonce);

        } catch (DBRecordNotFoundException e) {
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

    Response revokeCert(CertId id, CertRevokeRequest request, boolean caCert) {
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
        if (revReason == null) {
            logger.warn("CertService.revokeCert: request reason not recognised, set as Unspecified");
            revReason =	RevocationReason.UNSPECIFIED;
        }
        if (revReason == RevocationReason.REMOVE_FROM_CRL) {
            return unrevokeCert(id);
        }

        CAEngine engine = CAEngine.getInstance();

        X500Name caX500DN = null;
        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoRevoke-agent", getLocale(headers));
            processor.setCMSEngine(engine);
            processor.init();

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
            CertRecord targetRecord = clientRecord != null && id.toBigInteger().equals(clientSerialNumber) ? clientRecord : processor.getCertificateRecord(id);
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
            processor.init();

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

    CertData getCert(CertRetrievalRequest data, boolean generateNonce) throws Exception {

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
}
