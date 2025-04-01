//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.base;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.ServiceUnavailableException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CAEnabledException;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.ca.CANotLeafException;
import com.netscape.certsrv.ca.CATypeException;
import com.netscape.certsrv.ca.IssuerUnavailableException;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author ftweedal
 */
public class AuthorityRepository {
    private static Logger logger = LoggerFactory.getLogger(AuthorityRepository.class);

    private CAEngine engine;

    public AuthorityRepository(CAEngine engine) {
        this.engine = engine;
    }

    public List<AuthorityData> findCAs(final String id, final String parentID, final String dn, final String issuerDN) throws IOException {
        final X500Name x500dn = dn == null ? null : new X500Name(dn);
        final X500Name x500issuerDN = issuerDN == null ? null : new X500Name(issuerDN);
        logger.info("AuthorityRepository: Getting authorities:");

        return engine.getCAs().stream().
                map(this::readAuthorityData).
                filter(auth -> {
                    if (id != null && !id.equalsIgnoreCase(auth.getID())) return false;
                    if (parentID != null && !parentID.equalsIgnoreCase(auth.getParentID())) return false;
                    try {
                        if (x500dn != null && !x500dn.equals(new X500Name(auth.getDN()))) return false;
                        if (x500issuerDN != null && !x500issuerDN.equals(new X500Name(auth.getIssuerDN()))) return false;
                    } catch (IOException e) {
                        logger.error("AuthorityRepository: Unable to convert DNs for authority {}", auth.getID());
                        return false;
                    }
                    logger.info("AuthorityRepository: - ID: {}", auth.getID());
                    logger.info("AuthorityRepository:   DN: {}", auth.getDN());
                    if (auth.getParentID() != null) {
                        logger.info("AuthorityRepository:   Parent ID: {}", auth.getParentID());
                    }
                    logger.info("AuthorityRepository:   Issuer DN: {}", auth.getIssuerDN());
                    return true;
                }).
                collect(Collectors.toList());
    }

    public AuthorityData getCA(String authId) {
        logger.info("AuthorityRepository: Getting authority {}:", authId);

        AuthorityID aid = null;
        if (!AuthorityResource.HOST_AUTHORITY.equals(authId)) {
            try {
                aid = new AuthorityID(authId);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Bad AuthorityID: " + authId);
            }

        }
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + authId + "\" not found");

        AuthorityData authority = readAuthorityData(ca);

        logger.info("AuthorityRepository:   DN: {}", authority.getDN());
        if (authority.getParentID() != null) {
            logger.info("AuthorityRepository:   Parent ID: {}", authority.getParentID());
        }
        logger.info("AuthorityRepository:   Issuer DN: {}", authority.getIssuerDN());

        return authority;
    }


    public byte[] getBinaryCert(String authId) {

        logger.info("AuthorityRepository: Getting cert for authority {}", authId);

        AuthorityID aid = null;
        if (!AuthorityResource.HOST_AUTHORITY.equals(authId)) {
            try {
                aid = new AuthorityID(authId);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Bad AuthorityID: " + authId);
            }
        }
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + authId + "\" not found");

        org.mozilla.jss.crypto.X509Certificate cert = ca.getCaX509Cert();
        if (cert == null)
            throw new ResourceNotFoundException(
                "Certificate for CA \"" + authId + "\" not available");

        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException e) {
            // this really is a 500 Internal Server Error
            throw new PKIException("Error encoding certificate: " + e);
        }
    }

    public String getPemCert(String authId) {
        byte[] der = getBinaryCert(authId);
        return toPem("CERTIFICATE", der);
    }

    public byte[] getBinaryChain(String authId) {

        logger.info("AuthorityRepository: Getting cert chain for authority {}", authId);

        AuthorityID aid = null;
        if (!AuthorityResource.HOST_AUTHORITY.equals(authId)) {
            try {
                aid = new AuthorityID(authId);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Bad AuthorityID: " + authId);
            }
        }
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + authId + "\" not found");

        org.mozilla.jss.netscape.security.x509.CertificateChain chain = ca.getCACertChain();
        if (chain == null)
            throw new ResourceNotFoundException(
                "Certificate chain for CA \"" + authId + "\" not available");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            chain.encode(out);
        } catch (IOException e) {
            throw new PKIException("Error encoding certificate chain: " + e);
        }
        return out.toByteArray();
    }

    public String getPemChain(String authId) {
        byte[] der = getBinaryChain(authId);
        return toPem("PKCS7", der);
    }

    public AuthorityData createCA(AuthorityData data) {
        logger.info("AuthorityRepository: Creating authority {}", data.getDN());

        CertificateAuthority hostCA = engine.getCA();
        String parentAIDString = data.getParentID();
        AuthorityID parentAID = null;
        if (AuthorityResource.HOST_AUTHORITY.equals(parentAIDString)) {
            parentAID = hostCA.getAuthorityID();
        } else {
            try {
                parentAID = new AuthorityID(parentAIDString);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Bad Authority ID: " + parentAIDString, e);
            }
        }

        Map<String, String> auditParams = new LinkedHashMap<>();
        auditParams.put("dn", data.getDN());
        if (parentAID != null)
            auditParams.put("parent", parentAIDString);
        if (data.getDescription() != null)
            auditParams.put("description", data.getDescription());

        AuthToken authToken = (AuthToken) SessionContext.getContext().get(SessionContext.AUTH_TOKEN);
        try {
            CertificateAuthority subCA = engine.createCA(
                    parentAID,
                    authToken,
                    data.getDN(),
                    data.getDescription());
            audit(ILogger.SUCCESS, OpDef.OP_ADD,
                    subCA.getAuthorityID().toString(), auditParams);
            return readAuthorityData(subCA);
        } catch (IllegalArgumentException | BadRequestDataException e) {
            throw new BadRequestException(e.toString());
        } catch (CANotFoundException e) {
            throw new ResourceNotFoundException(e.toString());
        } catch (IssuerUnavailableException | CADisabledException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_ADD, "<unknown>", auditParams);
            throw new ConflictingOperationException(e.toString());
        } catch (CAMissingCertException | CAMissingKeyException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_CERT_NOT_FOUND", e.toString()), e);
            throw new ServiceUnavailableException(e.toString());
        } catch (Exception e) {
            String message = "Error creating CA: " + e.getMessage();
            logger.error(message, e);
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_ADD, "<unknown>", auditParams);
            throw new PKIException(message, e);
        }
    }

    public AuthorityData modifyCA(String authId, AuthorityData data) {
        logger.info("AuthorityRepository: Modifying authority {}", authId);

        AuthorityID aid = null;
        try {
            aid = new AuthorityID(authId);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + authId);
        }
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + authId + "\" not found");

        Map<String, String> auditParams = new LinkedHashMap<>();
        if (Boolean.valueOf(ca.getAuthorityEnabled()).equals(data.getEnabled())) {
            logger.info("AuthorityRepository:   enabled: {}", data.getEnabled());
            auditParams.put("enabled", data.getEnabled().toString());
        }

        String curDesc = ca.getAuthorityDescription();
        String newDesc = data.getDescription();
        if (curDesc != null && !curDesc.equals(newDesc)
                || curDesc == null && newDesc != null) {
            logger.info("AuthorityRepository:   description: {}", data.getDescription());
            auditParams.put("description", data.getDescription());
        }

        try {
            engine.modifyAuthority(ca, data.getEnabled(), data.getDescription());
            audit(ILogger.SUCCESS, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            return readAuthorityData(ca);
        } catch (CATypeException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            throw new ForbiddenException(e.toString());
        } catch (IssuerUnavailableException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            throw new ConflictingOperationException(e.toString());
        } catch (EBaseException e) {
            String message = "Error modifying authority: " + e.getMessage();
            logger.error(message, e);
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, ca.getAuthorityID().toString(), auditParams);
            throw new PKIException(message, e);
        }
    }

    public void renewCA(String authId, HttpServletRequest request) {
        logger.info("AuthorityRepository: Renewing cert for authority {}", authId);

        AuthorityID aid = null;
        try {
            aid = new AuthorityID(authId);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + authId);
        }
        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + authId + "\" not found");

        Map<String, String> auditParams = new LinkedHashMap<>();

        try {
            engine.renewAuthority(request, ca);
            audit(ILogger.SUCCESS, OpDef.OP_MODIFY, authId, null);
        } catch (CADisabledException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, authId, auditParams);
            throw new ConflictingOperationException(e.toString());
        } catch (Exception e) {
            String message = "Error renewing authority: " + e.getMessage();
            logger.error(message, e);
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_MODIFY, authId, auditParams);
            throw new PKIException(message, e);
        }
    }

    public void deleteCA(String authId, HttpServletRequest httpReq) {

        logger.info("AuthorityRepository: Deleting authority {}", authId);

        AuthorityID aid = null;
        try {
            aid = new AuthorityID(authId);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Bad AuthorityID: " + authId);
        }

        CertificateAuthority ca = engine.getCA(aid);

        if (ca == null)
            throw new ResourceNotFoundException("CA \"" + authId + "\" not found");

        Map<String, String> auditParams = new LinkedHashMap<>();

        try {
            engine.deleteAuthority(httpReq, ca);
            audit(ILogger.SUCCESS, OpDef.OP_DELETE, authId, null);
        } catch (CATypeException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_DELETE, authId, auditParams);
            throw new ForbiddenException(e.toString());
        } catch (CAEnabledException | CANotLeafException e) {
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_DELETE, authId, auditParams);
            throw new ConflictingOperationException(e.toString());
        } catch (EBaseException e) {
            String message = "Error modifying authority: " + e.getMessage();
            logger.error(message, e);
            auditParams.put("exception", e.toString());
            audit(ILogger.FAILURE, OpDef.OP_DELETE, authId, auditParams);
            throw new PKIException(message, e);
        }
    }

    private AuthorityData readAuthorityData(CertificateAuthority ca)
            throws PKIException {
        String dn;
        try {
            dn = ca.getX500Name().toLdapDNString();
        } catch (IOException e) {
            throw new PKIException("Error reading CA data: could not determine subject DN");
        }

        String issuerDN;
        BigInteger serial;
        try {
            issuerDN = ca.getCACert().getIssuerName().toString();
            serial = ca.getCACert().getSerialNumber();
        } catch (EBaseException e) {
            throw new PKIException("Error reading CA data: missing CA cert", e);
        }

        AuthorityID parentAID = ca.getAuthorityParentID();
        return new AuthorityData(
            ca.isHostAuthority(),
            dn,
            ca.getAuthorityID().toString(),
            parentAID != null ? parentAID.toString() : null,
            issuerDN,
            serial,
            ca.getAuthorityEnabled(),
            ca.getAuthorityDescription(),
            ca.isReady()
        );
    }

    private String toPem(String name, byte[] data) {
        return "-----BEGIN " + name + "-----\n" +
                Utils.base64encode(data, true) +
                "-----END " + name + "-----\n";
    }

    private void audit(
            String status, String op, String id,
            Map<String, String> params) {

        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.AUTHORITY_CONFIG,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(ScopeDef.SC_AUTHORITY, op, id, params));
        auditor.log(msg);
    }
}
