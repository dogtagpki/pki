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
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.NULL;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * RFC 2560:
 *
 * <pre>
 * UnknownInfo ::= NULL -- this can be replaced with an enumeration
 * </pre>
 *
 * @version $Revision$ $Date$
 */
public class UnknownInfo implements CertStatus {
    private static final Tag TAG = SEQUENCE.TAG;

    public UnknownInfo() {
    }

    public Tag getTag() {
        return Tag.get(2);
    }

    public void encode(Tag t, OutputStream os) throws IOException {
        NULL.getInstance().encode(getTag(), os);
    }

    public void encode(OutputStream os) throws IOException {
        encode(getTag(), os);
    }

    private static final Template templateInstance = new Template();

    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding <code>ResponseBytes</code>.
     */
    public static class Template implements ASN1Template {

        public Template() {
            //                     seqt = new SEQUENCE.Template();
            //                    seqt.addElement(new NULL.Template() );

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
            //  SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,
            //           istream);

            return new UnknownInfo();

        }
    }
}
