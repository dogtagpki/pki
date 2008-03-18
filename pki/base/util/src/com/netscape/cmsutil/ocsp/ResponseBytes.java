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

import org.mozilla.jss.asn1.*;
import java.io.*;

/**
 * RFC 2560:
 *
 * ResponseBytes ::=       SEQUENCE {
 *     responseType   OBJECT IDENTIFIER,
 *     response       OCTET STRING }
 *
 * $Revision: 14564 $ $Date: 2007-05-01 10:40:13 -0700 (Tue, 01 May 2007) $
 */
public class ResponseBytes implements ASN1Value
{
	///////////////////////////////////////////////////////////////////////
	// Members and member access
	///////////////////////////////////////////////////////////////////////
	public final static OBJECT_IDENTIFIER OCSP = 
		new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1");
	public final static OBJECT_IDENTIFIER OCSP_BASIC = 
		new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.48.1.1");

	private OBJECT_IDENTIFIER responseType = null;
	private OCTET_STRING response = null;
	private SEQUENCE sequence;

	public OBJECT_IDENTIFIER getObjectIdentifier()
	{
		return responseType;
	}

	public OCTET_STRING getResponse()
	{
		return response;
	}

	///////////////////////////////////////////////////////////////////////
	// Constructors
	///////////////////////////////////////////////////////////////////////
	private ResponseBytes() { }

	public ResponseBytes(OBJECT_IDENTIFIER responseType, OCTET_STRING response)
	{
		sequence = new SEQUENCE();

		this.responseType = responseType;
		sequence.addElement(responseType);

		this.response = response;
		sequence.addElement(response);
	}

	///////////////////////////////////////////////////////////////////////
	// encoding/decoding
	///////////////////////////////////////////////////////////////////////

	private static final Tag TAG = SEQUENCE.TAG;

	public Tag getTag()
	{
		return TAG;
	}

	public void encode(OutputStream ostream) throws IOException
	{
		encode(TAG, ostream);
	}

	public void encode(Tag implicitTag, OutputStream ostream)
		throws IOException
	{
		sequence.encode(implicitTag, ostream);
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
			seqt.addElement( OBJECT_IDENTIFIER.getTemplate() );
			seqt.addElement( OCTET_STRING.getTemplate() );
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
			SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

			return new ResponseBytes(
				(OBJECT_IDENTIFIER) seq.elementAt(0),
				(OCTET_STRING) seq.elementAt(1));
		}
	}
}
