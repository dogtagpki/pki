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
import org.mozilla.jss.asn1.*;
import java.security.Signer;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.cert.Certificate;

/**
 * RFC 2560:
 *
 * <pre>
 * BasicOCSPResponse       ::= SEQUENCE {
 *    tbsResponseData      ResponseData,
 *    signatureAlgorithm   AlgorithmIdentifier,
 *    signature            BIT STRING,
 *    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * </pre>
 *
 * @version $Revision$ $Date$
 */
public class BasicOCSPResponse implements Response
{
	private byte mData[] = null;
	private ResponseData _rd = null;
	private AlgorithmIdentifier _signAlg = null;
	private BIT_STRING _signature = null;
	private Certificate _certs[] = null;

	public BasicOCSPResponse(ResponseData rd, AlgorithmIdentifier signAlg,
			BIT_STRING signature, Certificate certs[])
	{
		_rd = rd;
		_signAlg = signAlg;
		_signature = signature;
		_certs = certs;
	}

	public BasicOCSPResponse(OCTET_STRING os)
	{
		mData = os.toByteArray();
	}

	public BasicOCSPResponse(byte data[])
	{
		mData = data;
	}

        private static final Tag TAG = SEQUENCE.TAG;

	public Tag getTag()
	{
		return TAG;
	}

        public void encode(Tag t, OutputStream os) throws IOException
        {
		os.write(mData);
	}

        public void encode(OutputStream os) throws IOException
        {
		os.write(mData);
        }

        public OCTET_STRING getBytes()
	{
		return null;
	}

	public ResponseData getResponseData()
	{
		return _rd;
	}

	public AlgorithmIdentifier getSignatureAlgorithm()
	{
		return _signAlg;
	}

	public BIT_STRING getSignature()
	{
		return _signature;
	}

	public int getCertsCount()
	{
		return _certs.length;
	}

	public Certificate getCertificateAt(int pos)
	{
		return _certs[pos];
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
                     seqt.addElement( ResponseData.getTemplate() );
                     seqt.addElement( AlgorithmIdentifier.getTemplate() );
                     seqt.addElement( BIT_STRING.getTemplate() );
                     seqt.addOptionalElement( new EXPLICIT.Template( 
			new Tag(0), new SEQUENCE.OF_Template( 
			Certificate.getTemplate())) );
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

                        ResponseData rd = (ResponseData)seq.elementAt(0);
                        AlgorithmIdentifier alg = 
				(AlgorithmIdentifier)seq.elementAt(1);
                        BIT_STRING bs = 
				(BIT_STRING)seq.elementAt(2);
                        return new BasicOCSPResponse(rd, alg, bs, null);
                }
        }
}
