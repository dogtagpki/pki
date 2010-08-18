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
 * OCSPRequest     ::=     SEQUENCE {
 *  tbsRequest                  TBSRequest,
 *  optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
 *
 * $Revision$ $Date$
 */

public class OCSPRequest implements ASN1Value
{

	///////////////////////////////////////////////////////////////////////
	// Members and member access
	///////////////////////////////////////////////////////////////////////
	private TBSRequest tbsRequest;
	private Signature optionalSignature;
	private SEQUENCE sequence;

	/**
	 * Returns the <code>TBSRequest</code> field.
	 */
	public TBSRequest getTBSRequest()
	{
		return tbsRequest;
	}

	/**
	 * Returns the <code>Signature</code> field.
	 */
	public Signature getSignature()
	{
		return optionalSignature;
	}

	///////////////////////////////////////////////////////////////////////
	// Constructors
	///////////////////////////////////////////////////////////////////////
	private OCSPRequest() { }

	/* THIS code is probably broken. It does not properly encode the explicit element */
       
	public OCSPRequest(TBSRequest tbsRequest, Signature optionalSignature)
	{
		sequence = new SEQUENCE();

		this.tbsRequest = tbsRequest;
		sequence.addElement(tbsRequest);

		this.optionalSignature = optionalSignature;
		if (optionalSignature != null) {
			sequence.addElement(optionalSignature);
		}
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

	public static Template getTemplate()
	{
		return templateInstance;
	}

	/**
 	* A Template for decoding OCSPRequest.
 	*/
	public static class Template implements ASN1Template
	{

		private SEQUENCE.Template seqt;

		public Template()
		{
			seqt = new SEQUENCE.Template();
			seqt.addElement(TBSRequest.getTemplate());
			seqt.addOptionalElement( new EXPLICIT.Template( new Tag(0),
				new Signature.Template()) );
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
			SEQUENCE seq = (SEQUENCE) seqt.decode(istream);
			Signature signature = null;
			if (seq.elementAt(1) != null) {
				signature = (Signature)((EXPLICIT)seq.elementAt(1)).getContent();
			}

			return new OCSPRequest(
				(TBSRequest) seq.elementAt(0),
				signature);
		}
	}
}
