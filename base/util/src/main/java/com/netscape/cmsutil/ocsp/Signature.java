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

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

/**
 * RFC 2560:
 *
 * <pre>
 * Signature       ::=     SEQUENCE {
 *  signatureAlgorithm   AlgorithmIdentifier,
 *  signature            BIT STRING,
 *  certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * </pre>
 *
 * @version $Revision$ $Date$
 */

public class Signature implements ASN1Value {
    ///////////////////////////////////////////////////////////////////////
    // Members and member access
    ///////////////////////////////////////////////////////////////////////
    private AlgorithmIdentifier signatureAlgorithm;
    private BIT_STRING signature;
    private SEQUENCE certs;
    private SEQUENCE sequence;

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public BIT_STRING getSignature() {
        return signature;
    }

    public int getCertificateCount() {
        if (certs == null) {
            return 0;
        } else {
            return certs.size();
        }
    }

    public Certificate getCertificateAt(int index) {
        if (certs == null) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return (Certificate) certs.elementAt(index);
    }

    public Signature(AlgorithmIdentifier signatureAlgorithm,
            BIT_STRING signature, SEQUENCE certs) {
        sequence = new SEQUENCE();

        this.signatureAlgorithm = signatureAlgorithm;
        sequence.addElement(signatureAlgorithm);

        this.signature = signature;
        sequence.addElement(signature);

        this.certs = certs;
        sequence.addElement(certs);
    }

    ///////////////////////////////////////////////////////////////////////
    // encode / decode
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
     * A Template for decoding Request.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(AlgorithmIdentifier.getTemplate());
            seqt.addElement(BIT_STRING.getTemplate());
            seqt.addOptionalElement(
                    new EXPLICIT.Template(
                            new Tag(0),
                            new SEQUENCE.OF_Template(new Certificate.Template())
                    )
                    );
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
            SEQUENCE certs = null;
            if (seq.elementAt(2) != null) {
                certs = (SEQUENCE) ((EXPLICIT) seq.elementAt(2)).getContent();
            }

            return new Signature(
                    (AlgorithmIdentifier) seq.elementAt(0),
                    (BIT_STRING) seq.elementAt(1),
                    certs);
        }
    }
}
