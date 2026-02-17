//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
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

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for CA agent certificate operations.
 * Replaces AgentCertServlet.
 *
 * Provides certificate review, revocation, and unrevocation for agents.
 */
@Path("v2/agent/certs")
public class CAAgentCertResource {

    private static final Logger logger = LoggerFactory.getLogger(CAAgentCertResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @GET
    @Path("{certId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response reviewCert(@PathParam("certId") String certIdStr) throws Exception {
        CertId id;
        try {
            id = new CertId(certIdStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + certIdStr);
        }

        try {
            CertData certData = getCertData(id);
            return Response.ok(certData.toJSON()).build();
        } catch (DBRecordNotFoundException e) {
            throw new CertNotFoundException(id);
        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    @POST
    @Path("{certId}/revoke-ca")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCACert(
            @PathParam("certId") String certIdStr,
            String requestData) throws Exception {
        return revoke(certIdStr, requestData, true);
    }

    @POST
    @Path("{certId}/revoke")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCert(
            @PathParam("certId") String certIdStr,
            String requestData) throws Exception {
        return revoke(certIdStr, requestData, false);
    }

    @POST
    @Path("{certId}/unrevoke")
    @Produces(MediaType.APPLICATION_JSON)
    public Response unrevokeCert(@PathParam("certId") String certIdStr) throws Exception {
        CertId id;
        try {
            id = new CertId(certIdStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + certIdStr);
        }

        logger.info("CAAgentCertResource: unrevoke on certificate {}", id.toHexString());
        CertRequestInfo info = unrevokeCert(id);
        if (info == null) {
            throw new PKIException("Error processing the certificate");
        }
        return Response.ok(info.toJSON()).build();
    }

    private Response revoke(String certIdStr, String requestData, boolean isCA) throws Exception {
        CertId id;
        try {
            id = new CertId(certIdStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + certIdStr);
        }

        logger.info("CAAgentCertResource: revoke on certificate {}", id.toHexString());

        CertRevokeRequest data = JSONSerializer.fromJSON(requestData, CertRevokeRequest.class);
        CertRequestInfo info = revokeCert(id, data, isCA);
        if (info == null) {
            throw new PKIException("Error processing the certificate");
        }
        return Response.ok(info.toJSON()).build();
    }

    private CertData getCertData(CertId id) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository repo = engine.getCertificateRepository();

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
        return certData;
    }

    private CertRequestInfo revokeCert(CertId id, CertRevokeRequest request, boolean caCert) {
        if (id == null) {
            throw new BadRequestException("Unable to revoke cert: Missing certificate ID");
        }
        if (request == null) {
            throw new BadRequestException("Unable to revoke cert: invalid request");
        }

        // Verify cert exists
        try {
            getCertData(id);
        } catch (DBRecordNotFoundException e) {
            throw new CertNotFoundException(id);
        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }

        CAEngine engine = engineQuarkus.getEngine();
        CertificateAuthority authority = engine.getCA();
        RevocationReason revReason = RevocationReason.valueOf(request.getReason());
        if (revReason == null) {
            logger.warn("CertService.revokeCert: request reason not recognised, set as Unspecified");
            revReason = RevocationReason.UNSPECIFIED;
        }
        if (revReason == RevocationReason.REMOVE_FROM_CRL) {
            return unrevokeCert(id);
        }

        RevocationProcessor processor;
        try {
            processor = new RevocationProcessor("caDoRevoke-agent", java.util.Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();
            processor.setStartTime(new Date().getTime());
            processor.setInitiative(AuditFormat.FROMAGENT);
            processor.setSerialNumber(id);
            processor.setRevocationReason(revReason);
            processor.setRequestType(revReason == RevocationReason.CERTIFICATE_HOLD
                    ? RevocationProcessor.ON_HOLD : RevocationProcessor.REVOKE);
            processor.setInvalidityDate(request.getInvalidityDate());
            processor.setComments(request.getComments());
            processor.setAuthority(authority);
        } catch (EBaseException e) {
            logger.error("Unable to revoke certificate: " + e.getMessage(), e);
            throw new PKIException("Unable to revoke certificate: " + e.getMessage(), e);
        }

        try {
            // Use the principal from SecurityIdentity for role checks
            PKIPrincipal principal = CAEngineQuarkus.toPKIPrincipal(identity);
            String subjectDN = principal.hasRole("Certificate Manager Agents") ? null : principal.getName();

            CertRecord targetRecord = processor.getCertificateRecord(id);
            X509CertImpl targetCert = targetRecord.getCertificate();

            processor.createCRLExtension();
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

    private CertRequestInfo unrevokeCert(CertId id) {
        if (id == null) {
            throw new BadRequestException("Unable to unrevoke certificate: Missing certificate ID");
        }

        logger.info("Unrevoking certificate {}", id.toHexString());

        try {
            getCertData(id);
        } catch (DBRecordNotFoundException e) {
            throw new CertNotFoundException(id);
        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }

        CAEngine engine = engineQuarkus.getEngine();
        CertificateAuthority authority = engine.getCA();
        RevocationProcessor processor;

        try {
            processor = new RevocationProcessor("caDoUnrevoke", java.util.Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();
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

    private CertRequestInfo getRequest(RequestId id) throws EBaseException {
        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        Request request = requestRepository.readRequest(id);
        if (request == null) {
            return null;
        }
        return CertRequestInfoFactory.create(request);
    }
}
