//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

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
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caCert",
        urlPatterns = "/v2/certs/*")
public class CertServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(CertServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("CertServlet.get(): session: {}", session.getId());

        PrintWriter out = response.getWriter();
        if(request.getPathInfo() != null) {
            CertId id;
            try {
                id = new CertId(request.getPathInfo().substring(1));
            } catch(NumberFormatException e) {
                throw new BadRequestException("Id not valid: " + request.getPathInfo().substring(1));
            }
            CertData cert;

            try {
                cert = getCertData(id);
                out.println(cert.toJSON());
            } catch (DBRecordNotFoundException e) {
                throw new CertNotFoundException(id);

            } catch (Exception e) {
                throw new PKIException(e.getMessage(), e);
            }
            return;
        }

        int maxTime = request.getParameter("maxTime") == null ?
                DEFAULT_MAXTIME : Integer.parseInt(request.getParameter("maxTime"));
        int size = request.getParameter("size") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));

        CertSearchRequest searchElems = CertSearchRequest.fromMap(request.getParameterMap());
        CertDataInfos infos = listCerts(searchElems, maxTime, start, size);
        out.println(infos.toJSON());
    }

    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("CertServlet.post(): session: {}", session.getId());

        if(request.getPathInfo() == null || !request.getPathInfo().equals("/search")) {
            throw new BadRequestException("Id not valid: " + request.getPathInfo().substring(1));
        }

        BufferedReader reader = request.getReader();
        String postMessage = reader.lines().collect(Collectors.joining());

        CertSearchRequest requestFilter = JSONSerializer.fromJSON(postMessage, CertSearchRequest.class);
        int size = request.getParameter("size") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));

        CertDataInfos infos = listCerts(requestFilter, start, size);

        PrintWriter out = response.getWriter();
        out.println(infos.toJSON());
    }

    private CertData getCertData(CertId id) throws Exception {
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

        return certData;
    }

    private CertDataInfos listCerts(CertSearchRequest searchReq, int start, int size) {
        return listCerts(searchReq, -1, start, size);
    }

    private CertDataInfos listCerts(CertSearchRequest searchReq, int maxTime, int start, int size) {
        CAEngine engine = getCAEngine();
        CertificateRepository repo = engine.getCertificateRepository();

        logger.info("Listing certificates");
        FilterBuilder builder = new FilterBuilder(searchReq);
        String filter = builder.buildFilter();

        logger.info("Search filter: " + filter);

        CertDataInfos infos = new CertDataInfos();
        try {
            Iterator<CertRecord> e = repo.searchCertificates(filter, maxTime, start, size);
            if (e == null) {
                throw new EBaseException("search results are null");
            }

            // store non-null results in a list
            List<CertDataInfo> results = new ArrayList<>();
            while (e.hasNext()) {
                CertRecord rec = e.next();
                if (rec == null) continue;
                results.add(createCertDataInfo(rec));
            }

            infos.setTotal(results.size());
            logger.info("Search results: " + results.size());
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
            X509Key x509Key = (X509Key)key;
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
