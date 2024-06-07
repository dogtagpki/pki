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

package org.dogtagpki.server.ca.rest.v1;

import java.io.ByteArrayOutputStream;
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

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.provider.RSAPublicKey;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfo;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertNotFoundException;
import com.netscape.certsrv.cert.CertResource;
import com.netscape.certsrv.cert.CertRetrievalRequest;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.cert.FilterBuilder;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertRecordList;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 */
public class CertService extends PKIService implements CertResource {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertService.class);

    CertificateRepository repo;
    SecureRandom random;

    public static final int DEFAULT_MAXTIME = 0;
    public static final int DEFAULT_MAXRESULTS = 20;

    public CertService() {

        CAEngine engine = CAEngine.getInstance();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

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

    String createSearchFilter(String status) {
        String filter;

        if (status == null) {
            filter = "(certstatus=*)"; // allCerts VLV

        } else  {
            filter = "(certStatus=" + LDAPUtil.escapeFilter(status) + ")";
        }

        return filter;
    }

    String createSearchFilter(CertSearchRequest data) {
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

    CertDataInfo createCertDataInfo(CertRecord record) throws EBaseException, InvalidKeyException {
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
