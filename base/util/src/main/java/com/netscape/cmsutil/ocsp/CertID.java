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
package com.netscape.cmsutil.ocsp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

/**
 * RFC 2560:
 *
 * <pre>
 * CertID          ::=     SEQUENCE {
 *     hashAlgorithm       AlgorithmIdentifier,
 *     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
 *     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
 *     serialNumber        CertificateSerialNumber }
 * </pre>
 *
 * @version $Revision$ $Date$
 */

public class CertID implements ASN1Value {
    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private AlgorithmIdentifier hashAlgorithm;
    private OCTET_STRING issuerNameHash;
    private OCTET_STRING issuerKeyHash;
    private INTEGER serialNumber;
    private SEQUENCE sequence;

    public AlgorithmIdentifier getHashAlgorithm() {
        return hashAlgorithm;
    }

    public OCTET_STRING getIssuerNameHash() {
        return issuerNameHash;
    }

    public OCTET_STRING getIssuerKeyHash() {
        return issuerKeyHash;
    }

    public INTEGER getSerialNumber() {
        return serialNumber;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    public CertID(AlgorithmIdentifier hashAlgorithm,
            OCTET_STRING issuerNameHash, OCTET_STRING issuerKeyHash,
            INTEGER serialNumber) {
        sequence = new SEQUENCE();

        this.hashAlgorithm = hashAlgorithm;
        sequence.addElement(hashAlgorithm);

        this.issuerNameHash = issuerNameHash;
        sequence.addElement(issuerNameHash);

        this.issuerKeyHash = issuerKeyHash;
        sequence.addElement(issuerKeyHash);

        this.serialNumber = serialNumber;
        sequence.addElement(serialNumber);
    }

    ///////////////////////////////////////////////////////////////////////
    // encoding/decoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;

    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();

    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding a <code>CertID</code>.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(AlgorithmIdentifier.getTemplate());
            seqt.addElement(OCTET_STRING.getTemplate());
            seqt.addElement(OCTET_STRING.getTemplate());
            seqt.addElement(INTEGER.getTemplate());
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
                throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                throws InvalidBERException, IOException {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new CertID(
                    (AlgorithmIdentifier) seq.elementAt(0),
                    (OCTET_STRING) seq.elementAt(1),
                    (OCTET_STRING) seq.elementAt(2),
                    (INTEGER) seq.elementAt(3));
        }
    }


    private static HashMap<OBJECT_IDENTIFIER, String> digestNames = new HashMap<>();

    static {
        digestNames.put(new OBJECT_IDENTIFIER("1.2.840.113549.2.2"), "MD2");
        digestNames.put(new OBJECT_IDENTIFIER("1.2.840.113549.2.5"), "MD5");
        digestNames.put(new OBJECT_IDENTIFIER("1.3.14.3.2.26"), "SHA-1");
        digestNames.put(new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.2.4"), "SHA-224");
        digestNames.put(new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.2.1"), "SHA-256");
        digestNames.put(new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.2.2"), "SHA-384");
        digestNames.put(new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.2.3"), "SHA-512");
    }

    public String getDigestName() {
        return digestNames.get(hashAlgorithm.getOID());
    }
}
