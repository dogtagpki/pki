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
 * OCSPResponse ::= SEQUENCE {
 *    responseStatus         OCSPResponseStatus,
 *    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 *
 * $Revision$ $Date$
 */
public class OCSPResponse implements ASN1Value
{
	///////////////////////////////////////////////////////////////////////
	// Members and member access
	///////////////////////////////////////////////////////////////////////
	private OCSPResponseStatus responseStatus = null;
	private ResponseBytes responseBytes = null;
	private SEQUENCE sequence;

	public OCSPResponseStatus getResponseStatus()
	{
		return responseStatus;
	}

	public ResponseBytes getResponseBytes()
	{
		return responseBytes;
	}

	///////////////////////////////////////////////////////////////////////
	// Constructors
	///////////////////////////////////////////////////////////////////////
	private OCSPResponse() { }

	public OCSPResponse(OCSPResponseStatus responseStatus,
		ResponseBytes responseBytes)
	{
		sequence = new SEQUENCE();

		this.responseStatus = responseStatus;
		sequence.addElement(responseStatus);

		this.responseBytes = responseBytes;
		sequence.addElement(new EXPLICIT(Tag.get(0), responseBytes));
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
	 * A Template for decoding an <code>OCSPResponse</code>.
	 */
	public static class Template implements ASN1Template
	{

		private SEQUENCE.Template seqt;

		public Template()
		{
			seqt = new SEQUENCE.Template();
			seqt.addElement( OCSPResponseStatus.getTemplate() );
			seqt.addOptionalElement(
				new EXPLICIT.Template(
					new Tag (0), new ResponseBytes.Template()) );

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

			OCSPResponseStatus rs = (OCSPResponseStatus) seq.elementAt(0);
			ResponseBytes rb = null;
			ASN1Value val = seq.elementAt(1);
			if (val instanceof EXPLICIT) {
				EXPLICIT exp = (EXPLICIT)val;
				rb = (ResponseBytes)exp.getContent();
			} else {
				rb = (ResponseBytes)val;
			}
			return new OCSPResponse(rs, rb);
		}
	}
}
