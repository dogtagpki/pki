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

import java.io.*;
import java.io.OutputStream;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.pkix.cert.Extension;

/**
 * RFC 2560:
 *
 * ResponseData ::= SEQUENCE {
 *    version              [0] EXPLICIT Version DEFAULT v1,
 *    responderID              ResponderID,
 *    producedAt               GeneralizedTime,
 *    responses                SEQUENCE OF SingleResponse,
 *    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 *
 * $Revision$ $Date$
 */
public class ResponseData implements ASN1Value
{
	private ResponderID mRID = null;
	private GeneralizedTime mProduced = null;
	private SingleResponse mSR[] = null;
	private Extension mExts[] = null;

	private static final Tag TAG = SEQUENCE.TAG;

	public ResponseData(ResponderID rid, GeneralizedTime produced, 
           SingleResponse sr[])
	{
		this(rid, produced, sr, null);
	}

	public ResponseData(ResponderID rid, GeneralizedTime produced, 
           SingleResponse sr[], Extension exts[])
	{
		mRID = rid;
                mProduced = produced;
		mSR = sr;
		mExts = exts;
	}
 
	public Tag getTag()
	{
		return TAG;
	}

	public void encode(OutputStream os) throws IOException
	{	
		encode(null, os);
	}

	public void encode(Tag t, OutputStream os) throws IOException
	{	
       		SEQUENCE seq = new SEQUENCE();
		seq.addElement(new EXPLICIT(Tag.get(0), new INTEGER(0)));
		seq.addElement(new EXPLICIT(mRID.getTag(), mRID));
		seq.addElement(mProduced);
       		SEQUENCE responses = new SEQUENCE();
		for (int i = 0; i < mSR.length; i++) {
			responses.addElement(mSR[i]);
		}
		seq.addElement(responses);
		if (mExts != null) {
       		SEQUENCE exts = new SEQUENCE();
			for (int i = 0; i < mExts.length; i++) {
				exts.addElement(mExts[i]);
			}
			seq.addElement(new EXPLICIT(Tag.get(1), exts));
		}
		if (t == null) {
                	seq.encode(os);
		} else {
                	seq.encode(t, os);
		}
	}	

	public ResponderID getResponderID()
	{
		return mRID;
	}

	public GeneralizedTime getProducedAt()
	{
		return mProduced;
	}

	public int getResponseCount()
	{
                if (mSR == null)
                  return 0;
                else 
		  return mSR.length;
	}

	public SingleResponse getResponseAt(int pos)
	{
                if (mSR == null)
		  return null;
                else 
		  return mSR[pos];
	}

	public int getResponseExtensionCount()
	{
		return 0;
	}

	public Extension getResponseExtensionAt(int pos)
	{
		return null;
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
                     seqt.addOptionalElement(new EXPLICIT.Template( 
                        new Tag (0), new INTEGER.Template()) );
                     seqt.addElement(new ANY.Template() );
                     seqt.addElement(new GeneralizedTime.Template() );
                     seqt.addElement(new SEQUENCE.OF_Template(
			SingleResponse.getTemplate()));
                     seqt.addOptionalElement(new EXPLICIT.Template(
			new Tag(1), new SEQUENCE.OF_Template(
			Extension.getTemplate())));

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

			INTEGER ver = null;
			EXPLICIT e_ver = (EXPLICIT)seq.elementAt(0);
			if (e_ver != null && e_ver.getTag().getNum() == 0) {
				ver = (INTEGER)e_ver.getContent();
			}
			ResponderID rid = null;
			ANY e_rid = (ANY)seq.elementAt(1);
			if (e_rid.getTag().getNum() == 1) {
				// name id
				rid = (NameID)
					NameID.getTemplate().decode(e_rid.getTag(),
					new ByteArrayInputStream(e_rid.getEncoded()));
			} else if (e_rid.getTag().getNum() == 2) {
				// key hash id
				rid = (KeyHashID)
					KeyHashID.getTemplate().decode(e_rid.getTag(),
					new ByteArrayInputStream(e_rid.getEncoded()));
			}
			GeneralizedTime producedAt = (GeneralizedTime)
				seq.elementAt(2);
			SEQUENCE responses = (SEQUENCE)seq.elementAt(3);
	                SingleResponse sr[] = null;
			if (responses.size() > 0) {
	                  sr = new SingleResponse[responses.size()];
                          for (int i = 0; i < responses.size(); i++) {
	                    sr[i] = (SingleResponse)responses.elementAt(i);
                          }
                        }
			return new ResponseData(rid, producedAt, sr);
                }
       }
}
