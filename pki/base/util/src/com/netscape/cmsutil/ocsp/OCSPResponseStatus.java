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
 * OCSPResponseStatus ::= ENUMERATED {
 *     successful            (0),  --Response has valid confirmations
 *     malformedRequest      (1),  --Illegal confirmation request
 *     internalError         (2),  --Internal error in issuer
 *     tryLater              (3),  --Try again later
 *                                 --(4) is not used
 *     sigRequired           (5),  --Must sign the request
 *     unauthorized          (6)   --Request unauthorized
 * }
 *
 * $Revision: 14564 $ $Date: 2007-05-01 10:40:13 -0700 (Tue, 01 May 2007) $
 */
public class OCSPResponseStatus implements ASN1Value
{
	///////////////////////////////////////////////////////////////////////
	// Members and member access
	///////////////////////////////////////////////////////////////////////
	public final static OCSPResponseStatus SUCCESSFUL = 
		new OCSPResponseStatus(0);
	public final static OCSPResponseStatus MALFORMED_REQUEST =
		new OCSPResponseStatus(1);
	public final static OCSPResponseStatus INTERNAL_ERROR =
		new OCSPResponseStatus(2);
	public final static OCSPResponseStatus TRY_LATER =
		new OCSPResponseStatus(3);
	public final static OCSPResponseStatus SIG_REQUIRED =
		new OCSPResponseStatus(5);
	public final static OCSPResponseStatus UNAUTHORIZED = 
		new OCSPResponseStatus(6);

	private ENUMERATED responseStatus;

	public long getValue()
	{
		return responseStatus.getValue();
	}

	///////////////////////////////////////////////////////////////////////
	// Constructors
	///////////////////////////////////////////////////////////////////////
	private OCSPResponseStatus() { }

	public OCSPResponseStatus(long val)
	{
		responseStatus = new ENUMERATED(val);
	}

	///////////////////////////////////////////////////////////////////////
	// encoding/decoding
	///////////////////////////////////////////////////////////////////////

	private static final Tag TAG = ENUMERATED.TAG;

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
		responseStatus.encode(implicitTag, ostream);
	}

	private static final Template templateInstance = new Template();

	public static Template getTemplate() {
		return templateInstance;
	}

	/**
	 * A Template for decoding an <code>OCSPResponseStatus</code>.
	 */
	public static class Template implements ASN1Template
	{
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
			ENUMERATED.Template enumt = new ENUMERATED.Template(); 
			ENUMERATED enum1 = (ENUMERATED) enumt.decode(implicitTag, istream);

			return new OCSPResponseStatus(enum1.getValue());
		}
	}
}
