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
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * RFC 2560:
 *
 * <pre>
 * ResponderID ::= CHOICE {
 *    byName               [1] EXPLICIT Name,
 *    byKey                [2] EXPLICIT KeyHash }
 * </pre>
 *
 * @version $Revision$ $Date$
 */
public class KeyHashID implements ResponderID
{
	private OCTET_STRING _hash = null; 
        private static final Tag TAG = SEQUENCE.TAG;

	public KeyHashID(OCTET_STRING hash)
	{
		_hash = hash;
	}

	public Tag getTag()
	{
		return Tag.get(2);
	}

	public void encode(Tag tag, OutputStream os) throws IOException
	{
               _hash.encode(os);
	}

	public void encode(OutputStream os) throws IOException
	{
               _hash.encode(os);
	}

	public OCTET_STRING getHash()
	{
		return _hash;
	}

        private static final Template templateInstance = new Template();

        public static Template getTemplate() {
                return templateInstance;
        }

        /**
         * A Template for decoding <code>ResponseBytes</code>.
         */
        public static class Template implements ASN1Template
        {

                private SEQUENCE.Template seqt;

                public Template()
                {
                     seqt = new SEQUENCE.Template();
//                     seqt.addElement(new EXPLICIT.Template(
 //                       new Tag (2), new OCTET_STRING.Template()) );
                       seqt.addElement(new OCTET_STRING.Template() );

                }

                public boolean tagMatch(Tag tag)
                {
                        return TAG.equals(tag);
                }

                public ASN1Value decode(InputStream istream)
                        throws InvalidBERException, IOException
                {
                        return decode(TAG, istream);
                }

                public ASN1Value decode(Tag implicitTag, InputStream istream)
                        throws InvalidBERException, IOException
                {
                        SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,
                                istream);

                        OCTET_STRING o = (OCTET_STRING)seq.elementAt(0);
                        return new KeyHashID(o);
                }
       }
}
