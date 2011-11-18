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
package com.netscape.certsrv.kra;


import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.X500Name;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;


/**
 * A class represents a proof of escrow. It indicates a key
 * pairs have been escrowed by appropriate authority. The 
 * structure of this object is very similar (if not exact) to 
 * X.509 certificate. A proof of escrow is signed by an escrow 
 * authority. It is possible to have a CMS policy to reject
 * the certificate issuance request if proof of escrow is not
 * presented.
 * <P>
 * Here is the ASN1 definition of a proof of escrow:
 * <PRE>
 * ProofOfEscrow ::= SIGNED {
 *   SEQUENCE {
 *     version [0] Version DEFAULT v1,
 *     serialNumber INTEGER,
 *     subjectName Name,
 *     issuerName Name,
 *     dateOfArchival Time,
 *     extensions [1] Extensions OPTIONAL
 *   }
 * }
 * </PRE>
 * <P>
 * 
 * @author thomask
 * @version $Revision$, $Date$
 */
public class ProofOfArchival implements IDBObj, IProofOfArchival, Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -2533562170977678799L;

    /**
     * Constants
     */
    public static final BigInteger DEFAULT_VERSION = new BigInteger("1");

    public static final String ATTR_VERSION = "pofVersion";
    public static final String ATTR_SERIALNO = "pofSerialNo";
    public static final String ATTR_SUBJECT = "pofSubject";
    public static final String ATTR_ISSUER = "pofIssuer";
    public static final String ATTR_DATE_OF_ARCHIVAL = "pofDateOfArchival";

    protected BigInteger mSerialNo = null;
    protected BigInteger mVersion = null;
    protected String mSubject = null;
    protected String mIssuer = null;
    protected Date mDateOfArchival = null;

    protected static Vector<String> mNames = new Vector<String>();
    static {
        mNames.addElement(ATTR_VERSION);
        mNames.addElement(ATTR_SERIALNO);
        mNames.addElement(ATTR_SUBJECT);
        mNames.addElement(ATTR_ISSUER);
        mNames.addElement(ATTR_DATE_OF_ARCHIVAL);
    }

    /**
     * Constructs a proof of escrow.
     * <P>
     * @param serialNo serial number of proof
     * @param subject subject name
     * @param issuer issuer name
     * @param dateOfArchival date of archival
     */
    public ProofOfArchival(BigInteger serialNo, String subject,
        String issuer, Date dateOfArchival) {
        mVersion = DEFAULT_VERSION;
        mSerialNo = serialNo;
        mSubject = subject;
        mIssuer = issuer;
        mDateOfArchival = dateOfArchival;
    }

    /**
     * Constructs proof of escrow from input stream.
     * <P>
     * @param in encoding source
     * @exception EBaseException failed to decode
     */
    public ProofOfArchival(InputStream in) throws EBaseException {
        decode(in);
    }

    /**
     * Sets an attribute value.
     * <P>
     * @param name attribute name
     * @param obj attribute value
     * @exception EBaseException failed to set attribute
     */
    public void set(String name, Object obj) throws EBaseException {
        if (name.equals(ATTR_VERSION)) {
            mVersion = (BigInteger) obj;
        } else if (name.equals(ATTR_SERIALNO)) {
            mSerialNo = (BigInteger) obj;
        } else if (name.equals(ATTR_SUBJECT)) {
            mSubject = (String) obj;
        } else if (name.equals(ATTR_ISSUER)) {
            mIssuer = (String) obj;
        } else if (name.equals(ATTR_DATE_OF_ARCHIVAL)) {
            mDateOfArchival = (Date) obj;
        } else {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    /**
     * Retrieves the value of an named attribute.
     * <P>
     * @param name attribute name
     * @return attribute value
     * @exception EBaseException failed to get attribute
     */
    public Object get(String name) throws EBaseException {
        if (name.equals(ATTR_VERSION)) {
            return mVersion;
        } else if (name.equals(ATTR_SERIALNO)) {
            return mSerialNo;
        } else if (name.equals(ATTR_SUBJECT)) {
            return mSubject;
        } else if (name.equals(ATTR_ISSUER)) {
            return mIssuer;
        } else if (name.equals(ATTR_DATE_OF_ARCHIVAL)) {
            return mDateOfArchival;
        } else {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }
	
    /**
     * Deletes an attribute.
     * <P>
     * @param name attribute name
     * @exception EBaseException failed to get attribute
     */
    public void delete(String name) throws EBaseException {
        throw new EBaseException(
                CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
    }
	
    /**
     * Retrieves a list of possible attribute names.
     * <P>
     *
     * @return a list of names
     */
    public Enumeration<String> getElements() {
        return mNames.elements();
    }

    /**
     * Retrieves serializable attribute names.
     * 
     * @return a list of serializable attribute names
     */
    public Enumeration<String> getSerializableAttrNames() {
        return mNames.elements();
    }
	
    /**
     * Retrieves version of this proof.
     * <P>
     * @return version 
     */
    public BigInteger getVersion() {
        return mVersion;
    }

    /**
     * Retrieves the serial number.
     * <P>
     * @return serial number 
     */
    public BigInteger getSerialNumber() {
        return mSerialNo;
    }

    /**
     * Retrieves the subject name.
     * <P>
     * @return subject name
     */
    public String getSubjectName() {
        return mSubject;
    }

    /**
     * Retrieves the issuer name.
     * <P>
     * @return issuer name
     */
    public String getIssuerName() {
        return mIssuer;
    }

    /**
     * Returns the beginning of the escrowed perioid.
     * <P>
     * @return date of archival
     */
    public Date getDateOfArchival() {
        return mDateOfArchival;
    }

    /**
     * Encodes this proof of escrow into the given 
     * output stream.
     * <P>
     */
    public void encode(DerOutputStream out) throws EBaseException {
        try {
            DerOutputStream seq = new DerOutputStream();

            // version (OPTIONAL)
            if (!mVersion.equals(DEFAULT_VERSION)) {
                DerOutputStream version = new DerOutputStream();

                version.putInteger(new BigInt(mVersion));
                seq.write(DerValue.createTag(
                        DerValue.TAG_CONTEXT, true, (byte) 0), 
                    version);
            }
	
            // serial number
            DerOutputStream serialno = new DerOutputStream();

            seq.putInteger(new BigInt(mSerialNo));

            // subject name
            DerOutputStream subject = new DerOutputStream();

            (new X500Name(mSubject)).encode(seq);

            // issuer name
            DerOutputStream issuer = new DerOutputStream();

            (new X500Name(mIssuer)).encode(seq);

            // issue date
            seq.putUTCTime(mDateOfArchival);
            out.write(DerValue.tag_Sequence, seq);	

        } catch (IOException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_DECODE_FAILED", e.toString()));
        }
    }

    /**
     * Encodes and signs this proof of escrow.
     * <P>
     */
    public void encodeAndSign(PrivateKey key, String algorithm, 
        String provider, DerOutputStream out) 
        throws EBaseException {

        try {
            Signature sigEngine = null;

            if (provider == null) {
                sigEngine = Signature.getInstance(algorithm);
            } else {
                sigEngine = Signature.getInstance(algorithm, 
                            provider);
            }

            sigEngine.initSign(key);
            DerOutputStream tmp = new DerOutputStream();

            encode(tmp);

            AlgorithmId sigAlgId = AlgorithmId.get(
                    sigEngine.getAlgorithm());

            sigAlgId.encode(tmp);
            byte dataToSign[] = tmp.toByteArray();

            sigEngine.update(dataToSign, 0, dataToSign.length);
            byte signature[] = sigEngine.sign();

            tmp.putBitString(signature);
            out.write(DerValue.tag_Sequence, tmp);
            return;
        } catch (NoSuchAlgorithmException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_ENCODE_FAILED_1", e.toString()));
        } catch (NoSuchProviderException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_ENCODE_FAILED_1", e.toString()));
        } catch (InvalidKeyException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_ENCODE_FAILED_1", e.toString()));
        } catch (SignatureException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_ENCODE_FAILED_1", e.toString()));
        } catch (IOException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_ENCODE_FAILED_1", e.toString()));
        }
    }

    /**
     * Decodes the input stream.
     * <P>
     */
    public void decode(InputStream in) throws EBaseException {
        try {
            // POA is a SIGNED ASN.1 macro, a three element sequence:
            // - Data to be signed (ToBeSigned) -- the "raw" data
            // - Signature algorithm (SigAlgId)
            // - The Signature bits

            DerValue val = new DerValue(in);

            DerValue seq[] = new DerValue[3]; 

            seq[0] = val.data.getDerValue();
            if (seq[0].tag == DerValue.tag_Sequence) {
                // with signature
                seq[1] = val.data.getDerValue();
                seq[2] = val.data.getDerValue();
                if (seq[1].data.available() != 0) {
                    throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_DECODE_FAILED_1", 
                                "no algorithm found"));
                }

                if (seq[2].data.available() != 0) {
                    throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_DECODE_FAILED_1", 
                                "no signature found"));
                }

                AlgorithmId algid = AlgorithmId.parse(seq[1]);
                byte signature[] = seq[2].getBitString();

                decodePOA(val, null);
            } else {
                // without signature
                decodePOA(val, seq[0]);
            }
        } catch (IOException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_DECODE_FAILED_1", e.toString()));
        }
    }

    /**
     * Decodes proof of escrow.
     * <P>
     */
    private void decodePOA(DerValue val, DerValue preprocessed) 
        throws EBaseException {
        try {
            DerValue tmp = null;

            if (preprocessed == null) {
                if (val.tag != DerValue.tag_Sequence) {
                    throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_DECODE_FAILED_1", 
                                "not start with sequence"));
                }
                tmp = val.data.getDerValue();
            } else {
                tmp = preprocessed;
            }

            // version
            if (tmp.isContextSpecific((byte) 0)) {
                if (tmp.isConstructed() && tmp.isContextSpecific()) {
                    DerValue version = tmp.data.getDerValue();
                    BigInt ver = version.getInteger();

                    mVersion = ver.toBigInteger();
                    tmp = val.data.getDerValue();
                }
            } else {
                mVersion = DEFAULT_VERSION;
            }

            // serial number
            DerValue serialno = tmp;

            mSerialNo = serialno.getInteger().toBigInteger();

            // subject
            DerValue subject = val.data.getDerValue();

            // mSubject = new X500Name(subject); // doesnt work
            mSubject = new String(subject.toByteArray());
		
            // issuer
            DerValue issuer = val.data.getDerValue();

            mIssuer = new String(issuer.toByteArray());

            // date of archival
            mDateOfArchival = val.data.getUTCTime();
        } catch (IOException e) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_POA_DECODE_FAILED_1", e.toString()));
        }
    }

    /**
     * Retrieves the string reprensetation of this 
     * proof of archival.
     */
    public String toString() {
        return "Version: " + mVersion.toString() + "\n" +
            "SerialNo: " + mSerialNo.toString() + "\n" +
            "Subject: " + mSubject + "\n" +
            "Issuer: " + mIssuer + "\n" +
            "DateOfArchival: " + mDateOfArchival.toString();
    }

}
