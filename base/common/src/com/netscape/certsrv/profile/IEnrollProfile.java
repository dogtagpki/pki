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
package com.netscape.certsrv.profile;

import com.netscape.certsrv.request.IRequest;

/**
 * This interface represents an enrollment profile.
 * <p>
 * An enrollment profile contains a list of enrollment specific input plugins, default policies, constriant policies and
 * output plugins.
 * <p>
 * This interface also defines a set of enrollment specific attribute names that can be used to retrieve values from an
 * enrollment request.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface IEnrollProfile extends IProfile {

    /**
     * Name of request attribute that stores the User
     * Supplied Certificate Request Type.
     */
    public static final String CTX_CERT_REQUEST_TYPE = "cert_request_type";

    /**
     * Name of request attribute that stores the User
     * Supplied Certificate Request.
     */
    public static final String CTX_CERT_REQUEST = "cert_request";

    /**
     * Possible values for CTX_CERT_REQUEST_TYPE attribute.
     */
    public static final String REQ_TYPE_PKCS10 = "pkcs10";
    public static final String REQ_TYPE_CRMF = "crmf";
    public static final String REQ_TYPE_CMC = "cmc";
    public static final String REQ_TYPE_KEYGEN = "keygen";

    /**
     * Name of request attribute that stores the End-User Locale.
     * <p>
     * The value is of type java.util.Locale.
     */
    public static final String REQUEST_LOCALE = "req_locale";

    /**
     * Name of request attribute that stores the sequence number. Consider
     * a CRMF request that may contain multiple certificate request.
     * The first sub certificate certificate request has a sequence
     * number of 0, the next one has a sequence of 1, and so on.
     * <p>
     * The value is of type java.lang.Integer.
     */
    public static final String REQUEST_SEQ_NUM = "req_seq_num";

    /**
     * Name of the request attribute that stores the sequence number for a
     * renewal request. Only one request at a time is permitted for a renewal.
     * This value corresponds to the sequence number (and hence the appropriate
     * certificate) of the original request
     */
    public static final String CTX_RENEWAL_SEQ_NUM = "renewal_seq_num";

    /**
     * Name of request attribute to indicate if this is a renewal
     */
    public static final String CTX_RENEWAL = "renewal";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Key.
     * <p>
     * The value is of type netscape.security.x509.CertificateX509Key
     */
    public static final String REQUEST_KEY = "req_key";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Subject Name.
     * <p>
     * The value is of type netscape.security.x509.CertificateSubjectName
     */
    public static final String REQUEST_SUBJECT_NAME = "req_subject_name";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Validity.
     * <p>
     * The value is of type netscape.security.x509.CertificateValidity
     */
    public static final String REQUEST_VALIDITY = "req_validity";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Signing Algorithm.
     * <p>
     * The value is of type netscape.security.x509.CertificateAlgorithmId
     */
    public static final String REQUEST_SIGNING_ALGORITHM = "req_signing_alg";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Extensions.
     * <p>
     * The value is of type netscape.security.x509.CertificateExtensions
     */
    public static final String REQUEST_EXTENSIONS = "req_extensions";

    /**
     * Name of request attribute that stores the End-User Supplied
     * PKI Archive Option extension. This extension is extracted
     * from a CRMF request that has the user-provided private key.
     * <p>
     * The value is of type byte []
     */
    public static final String REQUEST_ARCHIVE_OPTIONS = "req_archive_options";

    /**
     * Name of request attribute that stores the certificate template
     * that will be signed and then become a certificate.
     * <p>
     * The value is of type netscape.security.x509.X509CertInfo
     */
    public static final String REQUEST_CERTINFO = "req_x509info";

    /**
     * Name of request attribute that stores the issued certificate.
     * <p>
     * The value is of type netscape.security.x509.X509CertImpl
     */
    public static final String REQUEST_ISSUED_CERT = "req_issued_cert";

    /**
     * Name of request attribute that stores the transport certificate.
     * <p>
     * The value is of type String including base64 encoded certificate.
     */
    public static final String REQUEST_TRANSPORT_CERT = "req_transport_cert";

    /**
     * Set Default X509CertInfo in the request.
     *
     * @param request profile-based certificate request.
     * @exception EProfileException failed to set the X509CertInfo.
     */
    public void setDefaultCertInfo(IRequest request) throws EProfileException;
}
