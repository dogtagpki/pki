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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package netscape.security.pkcs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;

public class PKCS12 {

    // PKI OID: 2.16.840.1.113730.5
    public final static OBJECT_IDENTIFIER PKI_OID = new OBJECT_IDENTIFIER("2.16.840.1.113730.5");

    // PKCS #12 OID: 2.16.840.1.113730.5.1
    public final static OBJECT_IDENTIFIER PKCS12_OID = PKI_OID.subBranch(1);

    // PKCS #12 attributes OID: 2.16.840.1.113730.5.1.1
    public final static OBJECT_IDENTIFIER PKCS12_ATTRIBUTES_OID = PKCS12_OID.subBranch(1);

    // Certificate trust flags OID: 2.16.840.1.113730.5.1.1.1
    public final static OBJECT_IDENTIFIER CERT_TRUST_FLAGS_OID = PKCS12_ATTRIBUTES_OID.subBranch(1);

    // based on certdb.h in NSS
    public final static int TERMINAL_RECORD   = 1 << 0;
    public final static int TRUSTED           = 1 << 1;
    public final static int SEND_WARN         = 1 << 2;
    public final static int VALID_CA          = 1 << 3;
    public final static int TRUSTED_CA        = 1 << 4;
    public final static int NS_TRUSTED_CA     = 1 << 5;
    public final static int USER              = 1 << 6;
    public final static int TRUSTED_CLIENT_CA = 1 << 7;
    public final static int INVISIBLE_CA      = 1 << 8;
    public final static int GOVT_APPROVED_CA  = 1 << 9;

    public static boolean isFlagEnabled(int flag, int flags) {
        return (flag & flags) > 0;
    }

    // based on printflags() in secutil.c in NSS
    public static String encodeFlags(int flags) {

        StringBuffer sb = new StringBuffer();

        if (isFlagEnabled(VALID_CA, flags) && !isFlagEnabled(TRUSTED_CA, flags) && !isFlagEnabled(TRUSTED_CLIENT_CA, flags))
            sb.append("c");

        if (isFlagEnabled(TERMINAL_RECORD, flags) && !isFlagEnabled(TRUSTED, flags))
            sb.append("p");

        if (isFlagEnabled(TRUSTED_CA, flags))
            sb.append("C");

        if (isFlagEnabled(TRUSTED_CLIENT_CA, flags))
            sb.append("T");

        if (isFlagEnabled(TRUSTED, flags))
            sb.append("P");

        if (isFlagEnabled(USER, flags))
            sb.append("u");

        if (isFlagEnabled(SEND_WARN, flags))
            sb.append("w");

        if (isFlagEnabled(INVISIBLE_CA, flags))
            sb.append("I");

        if (isFlagEnabled(GOVT_APPROVED_CA, flags))
            sb.append("G");

        return sb.toString();
    }

    // based on CERT_DecodeTrustString() in certdb.c in NSS
    public static int decodeFlags(String flags) throws Exception {

        int value = 0;

        for (char c : flags.toCharArray()) {
            switch (c) {
            case 'p':
                value = value | TERMINAL_RECORD;
                break;

            case 'P':
                value = value | TRUSTED | TERMINAL_RECORD;
                break;

            case 'w':
                value = value | SEND_WARN;
                break;

            case 'c':
                value = value | VALID_CA;
                break;

            case 'T':
                value = value | TRUSTED_CLIENT_CA | VALID_CA;
                break;

            case 'C' :
                value = value | TRUSTED_CA | VALID_CA;
                break;

            case 'u':
                value = value | USER;
                break;

            case 'i':
                value = value | INVISIBLE_CA;
                break;
            case 'g':
                value = value | GOVT_APPROVED_CA;
                break;

            default:
                throw new Exception("Invalid trust flag: " + c);
            }
        }

        return value;
    }

    Map<BigInteger, PKCS12KeyInfo> keyInfosByID = new LinkedHashMap<BigInteger, PKCS12KeyInfo>();

    Map<BigInteger, PKCS12CertInfo> certInfosByID = new LinkedHashMap<BigInteger, PKCS12CertInfo>();

    public PKCS12() {
    }

    public Collection<PKCS12KeyInfo> getKeyInfos() {
        return keyInfosByID.values();
    }

    public void addKeyInfo(PKCS12KeyInfo keyInfo) {
        keyInfosByID.put(new BigInteger(1, keyInfo.id), keyInfo);
    }

    public PKCS12KeyInfo getKeyInfoByID(byte[] id) {
        return keyInfosByID.get(new BigInteger(1, id));
    }

    public PKCS12KeyInfo removeKeyInfoByID(byte[] id) {
        return keyInfosByID.remove(new BigInteger(1, id));
    }

    public Collection<PKCS12CertInfo> getCertInfos() {
        return certInfosByID.values();
    }

    public void addCertInfo(PKCS12CertInfo certInfo, boolean replace) {
        BigInteger id = new BigInteger(1, certInfo.getID());

        if (!replace && certInfosByID.containsKey(id))
            return;

        certInfosByID.put(id, certInfo);
    }

    public PKCS12CertInfo getCertInfoByID(byte[] id) {
        return certInfosByID.get(new BigInteger(1, id));
    }

    public Collection<PKCS12CertInfo> getCertInfosByNickname(String nickname) {

        Collection<PKCS12CertInfo> result = new ArrayList<PKCS12CertInfo>();

        for (PKCS12CertInfo certInfo : certInfosByID.values()) {
            if (!nickname.equals(certInfo.getNickname())) continue;
            result.add(certInfo);
        }

        return result;
    }

    public void removeCertInfoByNickname(String nickname) throws Exception {

        Collection<PKCS12CertInfo> result = getCertInfosByNickname(nickname);

        if (result.isEmpty()) {
            throw new Exception("Certificate not found: " + nickname);
        }

        for (PKCS12CertInfo certInfo : result) {
            // remove cert and key
            certInfosByID.remove(certInfo.getID());
            keyInfosByID.remove(certInfo.getID());
        }
    }
}
