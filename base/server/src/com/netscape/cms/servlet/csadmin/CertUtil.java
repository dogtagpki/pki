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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import org.dogtagpki.server.ca.ICertificateAuthority;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.pkcs11.PK11Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CertUtil {

    public final static Logger logger = LoggerFactory.getLogger(CertUtil.class);

    static final int LINE_COUNT = 76;

    public static X509CertImpl createLocalCert(
            IRequest req,
            CertInfoProfile profile,
            X509CertInfo info,
            java.security.PrivateKey signingPrivateKey,
            String caSigningKeyAlgo) throws Exception {

        profile.populate(req, info);

        X509CertImpl cert = CryptoUtil.signCert(signingPrivateKey, info, caSigningKeyAlgo);

        createCertRecord(req, profile, cert);

        // update request with cert
        req.setExtData(EnrollProfile.REQUEST_ISSUED_CERT, cert);

        return cert;
    }

    public static void createCertRecord(
            IRequest request,
            CertInfoProfile profile,
            X509Certificate cert) throws Exception {

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
        createCertRecord(request, profile, certImpl);
    }

    public static void createCertRecord(
            IRequest request,
            CertInfoProfile profile,
            X509CertImpl cert) throws Exception {

        logger.debug("CertUtil: createCertRecord(" +
                cert.getSerialNumber() + ", " +
                cert.getSubjectDN() + ")");

        CMSEngine engine = CMS.getCMSEngine();
        ICertificateAuthority ca = (ICertificateAuthority) engine.getSubsystem(ICertificateAuthority.ID);
        ICertificateRepository cr = ca.getCertificateRepository();

        MetaInfo meta = new MetaInfo();
        meta.set(ICertRecord.META_REQUEST_ID, request.getRequestId().toString());
        meta.set(ICertRecord.META_PROFILE_ID, profile.getProfileIDMapping());

        ICertRecord record = cr.createCertRecord(cert.getSerialNumber(), cert, meta);
        cr.addCertificateRecord(record);
    }

    /*
     * formats a cert fingerprints
     */
    public static String fingerPrintFormat(String content) {
        if (content == null || content.length() == 0) {
            return "";
        }

        StringBuffer result = new StringBuffer();
        result.append("Fingerprints:\n");

        while (content.length() >= LINE_COUNT) {
            result.append(content.substring(0, LINE_COUNT));
            result.append("\n");
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0)
            result.append(content);
        result.append("\n");

        return result.toString();
    }

    public static X509Certificate findCertificate(String fullnickname)
            throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        logger.debug("CertUtil: searching for cert " + fullnickname);

        try {
            return cm.findCertByNickname(fullnickname);

        } catch (ObjectNotFoundException e) {
            return null;
        }
    }

    public static void deleteCert(String tokenname, X509Certificate cert)
            throws Exception {

        logger.debug("CertUtil: deleting cert " + cert.getNickname());

        CryptoToken tok = CryptoUtil.getKeyStorageToken(tokenname);
        CryptoStore store = tok.getCryptoStore();

        if (store instanceof PK11Store) {
            PK11Store pk11store = (PK11Store) store;
            pk11store.deleteCertOnly(cert);
            logger.debug("CertUtil: cert deleted successfully");

        } else {
            logger.warn("CertUtil: unsupported crypto store: " + store.getClass().getName());
        }
    }
}
