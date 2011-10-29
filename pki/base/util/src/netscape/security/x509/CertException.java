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
package netscape.security.x509;

/**
 * CertException indicates one of a variety of certificate problems.
 *
 * @version 1.18
 *
 * @author David Brownell
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class CertException extends SecurityException {

    // Zero is reserved.

    /** Indicates that the signature in the certificate is not valid. */
    public static final int verf_INVALID_SIG = 1;

    /** Indicates that the certificate was revoked, and so is invalid. */
    public static final int verf_INVALID_REVOKED = 2;

    /** Indicates that the certificate is not yet valid. */
    public static final int verf_INVALID_NOTBEFORE = 3;

    /** Indicates that the certificate has expired and so is not valid. */
    public static final int verf_INVALID_EXPIRED = 4;

    /** Indicates that a certificate authority in the certification
     * chain is not trusted. */
    public static final int verf_CA_UNTRUSTED = 5;

    /** Indicates that the certification chain is too long. */
    public static final int verf_CHAIN_LENGTH = 6;

    /** Indicates an error parsing the ASN.1/DER encoding of the certificate. */
    public static final int verf_PARSE_ERROR = 7;

    /** Indicates an error constructing a certificate or certificate chain. */
    public static final int err_CONSTRUCTION = 8;

    /** Indicates a problem with the public key */
    public static final int err_INVALID_PUBLIC_KEY = 9;

    /** Indicates a problem with the certificate version */
    public static final int err_INVALID_VERSION = 10;
   
    /** Indicates a problem with the certificate format */
    public static final int err_INVALID_FORMAT = 11;
   
    /** Indicates a problem with the certificate encoding */
    public static final int err_ENCODING = 12;
   
    // Private data members
    private int		verfCode;
    private String	moreData;


    /**
     * Constructs a certificate exception using an error code
     * (<code>verf_*</code>) and a string describing the context
     * of the error.
     */
    public CertException(int code, String moredata)
    {
	verfCode = code;
	moreData = moredata;
    }

    /**
     * Constructs a certificate exception using just an error code,
     * without a string describing the context.
     */
    public CertException(int code)
    {
	verfCode = code;
    }

    /**
     * Returns the error code with which the exception was created.
     */
    public int getVerfCode() { return verfCode; }

    /**
     * Returns a string describing the context in which the exception
     * was reported.
     */
    public String getMoreData() { return moreData; }

    /**
     * Return a string corresponding to the error code used to create
     * this exception.
     */
    public String getVerfDescription()
    {
	switch (verfCode) {
        case verf_INVALID_SIG:
            return "The signature in the certificate is not valid.";
        case verf_INVALID_REVOKED:
            return "The certificate has been revoked.";
        case verf_INVALID_NOTBEFORE:
            return "The certificate is not yet valid.";
        case verf_INVALID_EXPIRED:
            return "The certificate has expired.";
        case verf_CA_UNTRUSTED:
            return "The Authority which issued the certificate is not trusted.";
        case verf_CHAIN_LENGTH:
            return "The certificate path to a trusted authority is too long.";
        case verf_PARSE_ERROR:
            return "The certificate could not be parsed.";
        case err_CONSTRUCTION:
            return "There was an error when constructing the certificate.";
        case err_INVALID_PUBLIC_KEY:
            return "The public key was not in the correct format.";
        case err_INVALID_VERSION:
            return "The certificate has an invalid version number.";      
        case err_INVALID_FORMAT:
            return "The certificate has an invalid format.";      
        case err_ENCODING:
            return "Problem encountered while encoding the data.";

        default:
            return "Unknown code:  " + verfCode;
	}
    }

    /**
     * Returns a string describing the certificate exception.
     */
    public String toString()
    {
	return "[Certificate Exception: " + getMessage() + "]";
    }

    /**
     * Returns a string describing the certificate exception.
     */
    public String getMessage()
    {
	return getVerfDescription()
		+ ( (moreData != null)
		    ? ( "\n  (" + moreData + ")" ) : "" );
    }
}
