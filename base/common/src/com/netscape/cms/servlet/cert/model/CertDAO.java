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
package com.netscape.cms.servlet.cert.model;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.cms.servlet.cert.CertResource;
import com.netscape.cms.servlet.request.model.CertRetrievalRequestData;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class CertDAO {

    private ICertificateRepository repo;
    private ICertificateAuthority ca;

    public CertDAO() {
        ca = (ICertificateAuthority) CMS.getSubsystem("ca");
        repo = ca.getCertificateRepository();
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
    public CertDataInfos listCerts(String filter, int maxResults, int maxTime, UriInfo uriInfo)
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
                list.add(createCertDataInfo(rec, uriInfo));
            }
        }

        CertDataInfos ret = new CertDataInfos();
        ret.setCertInfos(list);

        return ret;
    }

    public CertificateData getCert(CertRetrievalRequestData data) throws EBaseException, CertificateEncodingException {

        CertificateData certData = null;
        CertId certId = data.getCertId();

        //find the cert in question

        ICertRecord rec = null;
        BigInteger seq = certId.toBigInteger();

        rec = repo.readCertificateRecord(seq);
        X509CertImpl x509cert = null;

        if (rec != null) {
            x509cert = rec.getCertificate();
        }

        if (x509cert != null) {
            certData = new CertificateData();

            byte[] ba = null;
            String encoded64 = null;

            ba = x509cert.getEncoded();

            encoded64 = Utils.base64encode(ba);

            String prettyPrint = x509cert.toString();

            certData.setB64(encoded64);
            certData.setPrettyPrint(prettyPrint);

            String subjectNameStr = null;
            Principal subjectName = x509cert.getSubjectDN();

            if (subjectName != null) {
                subjectNameStr = subjectName.toString();
            }

            certData.setSubjectName(subjectNameStr);

            //Try to get the chain

            String p7Str = getCertChainData(x509cert);

            certData.setPkcs7CertChain(p7Str);

            certData.setSerialNo(certId);

            Date notBefore = x509cert.getNotBefore();
            Date notAfter = x509cert.getNotAfter();

            String notBeforeStr = null;
            String notAfterStr = null;

            if (notBefore != null) {
                notBeforeStr = notBefore.toString();
            }

            if (notAfter != null) {
                notAfterStr = notAfter.toString();
            }

            certData.setNotBefore(notBeforeStr);
            certData.setNotAfter(notAfterStr);

            String issuerNameStr = null;

            Principal issuerName = x509cert.getIssuerDN();

            if (issuerName != null) {
                issuerNameStr = issuerName.toString();
            }

            certData.setIssuerName(issuerNameStr);

        }

        return certData;
    }

    private CertDataInfo createCertDataInfo(ICertRecord rec, UriInfo uriInfo) throws EBaseException {
        CertDataInfo ret = new CertDataInfo();

        Path certPath = CertResource.class.getAnnotation(Path.class);
        BigInteger serial = rec.getSerialNumber();

        UriBuilder certBuilder = uriInfo.getBaseUriBuilder();
        certBuilder.path(certPath.value() + "/" + serial);
        ret.setCertURL(certBuilder.build().toString());

        return ret;
    }

    private String getCertChainData(X509CertImpl x509cert) {

        X509Certificate mCACerts[];

        if (x509cert == null) {
            return null;
        }

        try {
            mCACerts = ca.getCACertChain().getChain();
        } catch (Exception e) {
            mCACerts = null;
        }

        X509CertImpl[] certsInChain = new X509CertImpl[1];
        ;

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
