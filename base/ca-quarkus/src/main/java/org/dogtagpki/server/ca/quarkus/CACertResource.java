//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.provider.RSAPublicKey;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.servlet.cert.FilterBuilder;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;

/**
 * JAX-RS resource for CA certificate operations.
 * Replaces CertServlet.
 */
@Path("v2/certs")
public class CACertResource {

    private static final Logger logger = LoggerFactory.getLogger(CACertResource.class);
    private static final int DEFAULT_SIZE = 20;
    private static final int DEFAULT_MAXTIME = 10;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listCerts(
            @QueryParam("maxTime") Integer maxTime,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size,
            @QueryParam("status") String status,
            @QueryParam("minSerialNumber") String minSerialNumber,
            @QueryParam("maxSerialNumber") String maxSerialNumber) throws Exception {

        int effectiveMaxTime = maxTime != null ? maxTime : DEFAULT_MAXTIME;

        CertSearchRequest searchElems = new CertSearchRequest();
        if (status != null) searchElems.setStatus(status);
        if (minSerialNumber != null) searchElems.setSerialNumberRangeInUse(true);
        if (maxSerialNumber != null) searchElems.setSerialNumberRangeInUse(true);

        CertDataInfos infos = listCerts(searchElems, effectiveMaxTime, start, size);
        return Response.ok(infos.toJSON()).build();
    }

    @GET
    @Path("{certId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCert(@PathParam("certId") String certIdStr) throws Exception {
        CertId id;
        try {
            id = new CertId(certIdStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + certIdStr);
        }
        try {
            CertData cert = getCertData(id);
            return Response.ok(cert.toJSON()).build();
        } catch (DBRecordNotFoundException e) {
            throw new CertNotFoundException(id);
        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    @POST
    @Path("search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response searchCerts(
            String requestData,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {

        CertSearchRequest requestFilter = JSONSerializer.fromJSON(requestData, CertSearchRequest.class);
        CertDataInfos infos = listCerts(requestFilter, start, size);
        return Response.ok(infos.toJSON()).build();
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

    private CertDataInfos listCerts(CertSearchRequest searchReq, int start, int size) {
        return listCerts(searchReq, -1, start, size);
    }

    private CertDataInfos listCerts(CertSearchRequest searchReq, int maxTime, int start, int size) {
        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository repo = engine.getCertificateRepository();

        logger.info("Listing certificates");
        FilterBuilder builder = new FilterBuilder(searchReq);
        String filter = builder.buildFilter();
        logger.info("Search filter: {}", filter);

        CertDataInfos infos = new CertDataInfos();
        try {
            Iterator<CertRecord> e = repo.searchCertificates(filter, maxTime, start, size);
            if (e == null) {
                throw new EBaseException("search results are null");
            }

            List<CertDataInfo> results = new ArrayList<>();
            while (e.hasNext()) {
                CertRecord rec = e.next();
                if (rec == null) continue;
                results.add(createCertDataInfo(rec));
            }

            logger.info("Search results: {}", results.size());
            infos.setEntries(results);
        } catch (Exception e) {
            logger.error("Unable to list certificates: " + e.getMessage(), e);
            throw new PKIException("Unable to list certificates: " + e.getMessage(), e);
        }
        return infos;
    }

    private CertDataInfo createCertDataInfo(CertRecord certRecord) throws EBaseException, InvalidKeyException {
        CertDataInfo info = new CertDataInfo();

        CertId id = new CertId(certRecord.getSerialNumber());
        info.setID(id);

        X509Certificate cert = certRecord.getCertificate();
        info.setIssuerDN(cert.getIssuerDN().toString());
        info.setSubjectDN(cert.getSubjectDN().toString());
        info.setStatus(certRecord.getStatus());
        info.setVersion(cert.getVersion());
        info.setType(cert.getType());

        PublicKey key = cert.getPublicKey();
        if (key instanceof X509Key) {
            X509Key x509Key = (X509Key) key;
            info.setKeyAlgorithmOID(x509Key.getAlgorithmId().getOID().toString());

            if (x509Key.getAlgorithmId().toString().equalsIgnoreCase("RSA")) {
                RSAPublicKey rsaKey = new RSAPublicKey(x509Key.getEncoded());
                info.setKeyLength(rsaKey.getKeySize());
            }
        }

        info.setNotValidBefore(cert.getNotBefore());
        info.setNotValidAfter(cert.getNotAfter());
        info.setIssuedOn(certRecord.getCreateTime());
        info.setIssuedBy(certRecord.getIssuedBy());
        info.setRevokedOn(certRecord.getRevokedOn());
        info.setRevokedBy(certRecord.getRevokedBy());

        return info;
    }
}
