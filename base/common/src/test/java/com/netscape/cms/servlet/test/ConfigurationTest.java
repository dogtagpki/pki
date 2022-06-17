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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.POPOPrivKey;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

/**
 * @author alee
 *
 */
public class ConfigurationTest {

    private ConfigurationTest() {
    }

    public static String generateCRMFRequest(CryptoToken token, String keysize, String subjectdn, boolean dualkey)
            throws NoSuchAlgorithmException, TokenException, IOException, InvalidBERException {
        KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);

        Integer x = Integer.valueOf(keysize);
        int key_len = x.intValue();

        kg.initialize(key_len);

        // 1st key pair
        KeyPair pair = kg.genKeyPair();

        // create CRMF
        CertTemplate certTemplate = new CertTemplate();

        certTemplate.setVersion(new INTEGER(2));

        if (subjectdn != null) {
            X500Name name = new X500Name(subjectdn);
            ByteArrayInputStream cs = new ByteArrayInputStream(name.getEncoded());
            Name n = (Name) Name.getTemplate().decode(cs);
            certTemplate.setSubject(n);
        }

        certTemplate.setPublicKey(new SubjectPublicKeyInfo(pair.getPublic()));

        SEQUENCE seq = new SEQUENCE();
        CertRequest certReq = new CertRequest(new INTEGER(1), certTemplate,
                seq);
        byte popdata[] = { 0x0, 0x3, 0x0 };

        ProofOfPossession pop = ProofOfPossession.createKeyEncipherment(
                POPOPrivKey.createThisMessage(new BIT_STRING(popdata, 3)));

        CertReqMsg crmfMsg = new CertReqMsg(certReq, pop, null);

        SEQUENCE s1 = new SEQUENCE();

        // 1st : Encryption key

        s1.addElement(crmfMsg);

        // 2nd : Signing Key

        if (dualkey) {
            System.out.println("dualkey = true");
            SEQUENCE seq1 = new SEQUENCE();
            CertRequest certReqSigning = new CertRequest(new INTEGER(1),
                    certTemplate, seq1);
            CertReqMsg signingMsg = new CertReqMsg(certReqSigning, pop, null);

            s1.addElement(signingMsg);
        }

        byte encoded[] = ASN1Util.encode(s1);

        // BASE64Encoder encoder = new BASE64Encoder();
        // String Req1 = encoder.encodeBuffer(encoded);
        String Req1 = Utils.base64encode(encoded, true);
        return Req1;
    }
}
