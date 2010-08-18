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

import org.mozilla.jss.pkix.cert.Extension;
import org.mozilla.jss.asn1.*;
import java.io.*;

/**
 * RFC 2560:
 *
 * <pre>
 * TBSRequest      ::=     SEQUENCE {
 *  version             [0] EXPLICIT Version DEFAULT v1,
 *  requestorName       [1] EXPLICIT GeneralName OPTIONAL,
 *  requestList             SEQUENCE OF Request,
 *  requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @version $Revision$ $Date$
 */

public class TBSRequest implements ASN1Value
{
	///////////////////////////////////////////////////////////////////////
	// members and member access
	///////////////////////////////////////////////////////////////////////
	private static final INTEGER version = new INTEGER (1);
	private ANY requestorName;
	private SEQUENCE requestList;
	private SEQUENCE requestExtensions;
	private SEQUENCE sequence;

	public INTEGER getVersion()
	{
		return version;
	}

	public ANY getRequestorName()
	{
		return requestorName;
	}	

	public int getRequestCount()
	{
		if( requestList == null ) {
				return 0;
		} else {
				return requestList.size();
		}
	}

	public Request getRequestAt(int index)
	{
		return (Request) requestList.elementAt(index);
	}

	public int getExtensionsCount()
	{
		if( requestExtensions == null ) {
				return 0;
		} else {
				return requestExtensions.size();
		}
	}

	public Extension getRequestExtensionAt(int index)
	{
		return (Extension) requestExtensions.elementAt(index);
	}

	///////////////////////////////////////////////////////////////////////
	// constructors
	///////////////////////////////////////////////////////////////////////
	/* this code is probably broken - it doesn't do appropriate tagging */
	private TBSRequest() {}

	public TBSRequest(INTEGER version, ANY requestorName,
		SEQUENCE requestList, SEQUENCE requestExtensions)
	{
		sequence = new SEQUENCE();

		if (version != null) {
			sequence.addElement (version);
		}

		this.requestorName = requestorName;
		if (requestorName != null) {
			sequence.addElement (requestorName);
		}

		this.requestList = requestList;
		sequence.addElement (requestList);

		this.requestExtensions = requestExtensions;
		if (requestExtensions != null) {
			sequence.addElement (requestExtensions);
		}
	}

	///////////////////////////////////////////////////////////////////////
	// encode / decode
	///////////////////////////////////////////////////////////////////////
	public static final Tag TAG = SEQUENCE.TAG;

	public Tag getTag()
	{
		return TAG;
	}

	public void encode(OutputStream ostream)
		throws IOException
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
 	* A Template for decoding POPOSigningKey.
 	*/
	public static class Template implements ASN1Template
	{

		private SEQUENCE.Template seqt;

		public Template()
		{
			seqt = new SEQUENCE.Template();
			seqt.addElement(
				new EXPLICIT.Template(
					new Tag(0), new INTEGER.Template()),
                new EXPLICIT( new Tag(0), new INTEGER(0)) 
            );
			seqt.addOptionalElement(
				new EXPLICIT.Template(
					new Tag (1), new ANY.Template()) );
			seqt.addElement( new SEQUENCE.OF_Template(new Request.Template()) );
			seqt.addOptionalElement(new EXPLICIT.Template(new Tag(2),
				new SEQUENCE.OF_Template(new Extension.Template())) );
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

			EXPLICIT exts = (EXPLICIT) seq.elementAt(3);
			SEQUENCE exts_seq;
			if (exts != null) {
				exts_seq = (SEQUENCE)exts.getContent();
			} else {
				exts_seq = null;
			}

			INTEGER v = (INTEGER)	((EXPLICIT)seq.elementAt(0)).getContent();
			ANY requestorname = null;
			if (seq.elementAt(1) != null) {
				requestorname = (ANY) ((EXPLICIT)seq.elementAt(1)).getContent();
			}

			return new TBSRequest(
				v,
				requestorname,
				(SEQUENCE) seq.elementAt(2),
				exts_seq);
		}
	}
}
