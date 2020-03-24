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
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkix.cert.Extension;

/**
 * RFC 2560:
 *
 * <pre>
 *   Request         ::=     SEQUENCE {
 *     reqCert                     CertID,
 *     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @version $Revision$ $Date$
 */

public class Request implements ASN1Value {
    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private CertID reqCert = null;
    private SEQUENCE singleRequestExtensions = null;
    private SEQUENCE sequence = null;

    public CertID getCertID() {
        return reqCert;
    }

    public int getExtensionsCount() {
        if (singleRequestExtensions == null) {
            return 0;
        } else {
            return singleRequestExtensions.size();
        }
    }

    public Extension getRequestExtensionAt(int index) {
        if (singleRequestExtensions == null) {
            throw new ArrayIndexOutOfBoundsException();
        }
        return (Extension) singleRequestExtensions.elementAt(index);
    }

    public Request(CertID reqCert, SEQUENCE singleRequestExtensions) {
        sequence = new SEQUENCE();

        this.reqCert = reqCert;
        sequence.addElement(reqCert);

        if (singleRequestExtensions != null) {
            this.singleRequestExtensions = singleRequestExtensions;
            sequence.addElement(singleRequestExtensions);
        }
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
            seqt.addElement(CertID.getTemplate());
            seqt.addOptionalElement(new EXPLICIT.Template(new Tag(0),
                    new SEQUENCE.OF_Template(new Extension.Template())));
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

            EXPLICIT tag = (EXPLICIT) seq.elementAt(1);

            if (tag == null) {
                return new Request(
                        (CertID) seq.elementAt(0),
                        (SEQUENCE) null);
            } else {
                return new Request(
                        (CertID) seq.elementAt(0),
                        (SEQUENCE) tag.getContent());
            }
        }
    }
}
