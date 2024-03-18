//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.v2;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAServlet;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.security.JssSubsystem;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caCert-agent",
        urlPatterns = "/v2/agent/certs/*")
public class AgentCertServlet extends CAServlet{
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(AgentCertServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        if(request.getPathInfo() == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }

        CertId id;
        try {
            id = new CertId(request.getPathInfo().substring(1));
        } catch(NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + request.getPathInfo().substring(1));
        }
        CertData certData = null;

        try {
            certData = getCertData(request, id, true);
            PrintWriter out = response.getWriter();
            out.println(certData.toJSON());
        } catch (EDBRecordNotFoundException e) {
            throw new CertNotFoundException(id);

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }
    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AgentCertRequestServlet.post(): session: {}", session.getId());

        if (request.getPathInfo() == null || request.getPathInfo().isEmpty()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");

        if (pathElement.length != 2) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }
        CertId id;
        try {
            id = new CertId(pathElement[0]);
        } catch(NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + pathElement[0]);
        }
        CertRequestInfo info = null;
        if (pathElement[1].matches("revoke-ca|revoke")) {
            logger.info("AgentCertServlet: operation {} on certificate {}",pathElement[1], id.toHexString());
            BufferedReader reader = request.getReader();
            String postMessage = reader.lines().collect(Collectors.joining());

            CertRevokeRequest data;
            try {
                data = JSONSerializer.fromJSON(postMessage, CertRevokeRequest.class);
            } catch (JsonProcessingException ex) {
                throw new BadRequestException(ex.getMessage());
            }
            info = revokeCert(request, id, data, pathElement[1].equals("revoke-ca"));
        }
        if (pathElement[1].equals("unrevoke")) {
            logger.info("AgentCertServlet: operation {} on certificate {}",pathElement[1], id.toHexString());
            info = unrevokeCert(request, id);
        }
        if (info != null) {
            PrintWriter out = response.getWriter();
            out.print(info.toJSON());
            return;
        }
        logger.debug("AgentCertServlet: not existing operation {} for certificate {}",pathElement[1], id.toHexString());
        throw new ResourceNotFoundException("Action not present:" + pathElement[1]);
    }

    private CertData getCertData(HttpServletRequest servletRequest, CertId id, boolean generateNonce) throws Exception {
        CAEngine engine = getCAEngine();
        CertificateRepository repo = engine.getCertificateRepository();

         //find the cert in question
        CertRecord certRecord = repo.readCertificateRecord(id.toBigInteger());
        X509CertImpl cert = certRecord.getCertificate();

        CertData certData = new CertData();
        certData.setSerialNumber(id);

        Principal issuerDN = cert.getIssuerName();
        if (issuerDN != null) certData.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectName();
        if (subjectDN != null) certData.setSubjectDN(subjectDN.toString());

        String base64 = CertUtil.toPEM(cert);

        certData.setEncoded(base64);

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

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");
        Date notBefore = cert.getNotBefore();
        if (notBefore != null) certData.setNotBefore(sdf.format(notBefore));

        Date notAfter = cert.getNotAfter();
        if (notAfter != null) certData.setNotAfter(sdf.format(notAfter));

        certData.setRevokedOn(certRecord.getRevokedOn());
        certData.setRevokedBy(certRecord.getRevokedBy());

        RevocationInfo revInfo = certRecord.getRevocationInfo();
        if (revInfo != null) {
            CRLExtensions revExts = revInfo.getCRLEntryExtensions();
            if (revExts != null) {
                try {
                    CRLReasonExtension ext = (CRLReasonExtension)
                        revExts.get(CRLReasonExtension.NAME);
                    certData.setRevocationReason(ext.getReason().getCode());
                } catch (X509ExtensionException e) {
                    logger.debug("CRL extension error for certificate {}", id.toHexString());
                }
            }
        }

        certData.setStatus(certRecord.getStatus());
        if (engine.getEnableNonces() && generateNonce) {
            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            SecureRandom random = jssSubsystem.getRandomNumberGenerator();
            // generate nonce
            long n = random.nextLong();
            // store nonce in session
            Map<Object, Long> nonces = engine.getNonces(servletRequest, "cert-revoke");
            nonces.put(id.toBigInteger(), n);
            // return nonce to client
            certData.setNonce(n);
        }

        return certData;
    }

    private CertRequestInfo revokeCert(HttpServletRequest servletRequest, CertId id, CertRevokeRequest request, boolean caCert) {
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
        try {
            @SuppressWarnings("unused")
            CertData data = getCertData(servletRequest, id, false);
        } catch (EDBRecordNotFoundException e) {
            throw new CertNotFoundException(id);

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
        CertificateAuthority authority = getCAEngine().getCA();
        RevocationReason revReason = RevocationReason.valueOf(request.getReason());
        if (revReason == null) {
            logger.warn("CertService.revokeCert: request reason not recognised, set as Unspecified");
            revReason = RevocationReason.UNSPECIFIED;
        }
        if (revReason == RevocationReason.REMOVE_FROM_CRL) {
            return unrevokeCert(servletRequest, id);
        }

        CAEngine engine = CAEngine.getInstance();

        X500Name caX500DN = null;
        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoRevoke-agent", servletRequest.getLocale());
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
            return getRequest(certRequest.getRequestId());

        } catch (EBaseException e) {
            logger.error("Unable to create revocation response: " + e.getMessage(), e);
            throw new PKIException("Unable to create revocation response: " + e.getMessage(), e);
        }
    }

    private CertRequestInfo unrevokeCert(HttpServletRequest servletRequest, CertId id) {

        if (id == null) {
            logger.warn("Unable to unrevoke certificate: Missing certificate ID");
            throw new BadRequestException("Unable to unrevoke certificate: Missing certificate ID");
        }

        logger.info("Unrevoking certificate {}", id.toHexString());

        // check cert actually exists.  This will throw a CertNotFoundException
        // if the cert does not exist
        try {
            @SuppressWarnings("unused")
            CertData data = getCertData(servletRequest, id, false);
        } catch (EDBRecordNotFoundException e) {
            throw new CertNotFoundException(id);

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }

        CAEngine engine = getCAEngine();
        CertificateAuthority authority = engine.getCA();
        RevocationProcessor processor;

        try {
            processor = new RevocationProcessor("caDoUnrevoke", servletRequest.getLocale());
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
            return getRequest(certRequest.getRequestId());

        } catch (EBaseException e) {
            logger.error("Unable to create unrevocation response: " + e.getMessage(), e);
            throw new PKIException("Unable to create unrevocation response: " + e.getMessage(), e);
        }
    }
    /**
     * Gets info for a specific request
     *
     * @param id
     * @return info for specific request
     * @throws EBaseException
     */
    private CertRequestInfo getRequest(RequestId id) throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        RequestRepository requestRepository = engine.getRequestRepository();

        Request request = requestRepository.readRequest(id);
        if (request == null) {
            return null;
        }
        return CertRequestInfoFactory.create(request);
    }

}
