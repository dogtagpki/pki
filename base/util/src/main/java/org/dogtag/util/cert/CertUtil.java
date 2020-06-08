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
package org.dogtag.util.cert;

import java.security.cert.X509Certificate;
import java.util.StringTokenizer;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.pkcs11.PK11Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmsutil.crypto.CryptoUtil;

public class CertUtil {

    public final static Logger logger = LoggerFactory.getLogger(CertUtil.class);

    static final int LINE_COUNT = 76;

    public static byte[] parseCSR(String csr) {

        if (csr == null) {
            return null;
        }

        csr = csr.replaceAll(Cert.REQUEST_HEADER, "");
        csr = csr.replaceAll("-----BEGIN NEW CERTIFICATE REQUEST-----", "");
        csr = csr.replaceAll(Cert.REQUEST_FOOTER, "");
        csr = csr.replaceAll("-----END NEW CERTIFICATE REQUEST-----", "");

        StringBuffer sb = new StringBuffer();
        StringTokenizer st = new StringTokenizer(csr, "\r\n ");

        while (st.hasMoreTokens()) {
            String nextLine = st.nextToken();

            nextLine = nextLine.trim();
            if (nextLine.equals(Cert.REQUEST_HEADER))
                continue;
            if (nextLine.equals("-----BEGIN NEW CERTIFICATE REQUEST-----"))
                continue;
            if (nextLine.equals(Cert.REQUEST_FOOTER))
                continue;
            if (nextLine.equals("-----END NEW CERTIFICATE REQUEST-----"))
                continue;
            sb.append(nextLine);
        }

        return Utils.base64decode(sb.toString());
    }

    public static String toPEM(X509Certificate cert) throws Exception {
        return Cert.HEADER + "\n" +
                Utils.base64encodeMultiLine(cert.getEncoded()) +
                Cert.FOOTER + "\n";
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

    public static org.mozilla.jss.crypto.X509Certificate findCertificate(String fullnickname)
            throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        logger.debug("CertUtil: searching for cert " + fullnickname);

        try {
            return cm.findCertByNickname(fullnickname);

        } catch (ObjectNotFoundException e) {
            return null;
        }
    }

    public static void deleteCert(String tokenname, org.mozilla.jss.crypto.X509Certificate cert)
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
