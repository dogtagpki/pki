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
package com.netscape.cmscore.request;

/**
 * temporary location for cert request constants.
 * XXX we really need to centralize all these but for now they are here
 * as needed.
 */
public class CertRequestConstants {
    // request types - these have string values.
    // made to match policy constants.
    public final static String GETCRL_REQUEST = "getCRL";
    public final static String GETCACHAIN_REQUEST = "getCAChain";
    public final static String GETREVOCATIONINFO_REQUEST = "getRevocationInfo";

    public final static String REVOCATION_CHECK_CHALLENGE_REQUEST = "checkChallengePhrase";
    public final static String GETCERTS_FOR_CHALLENGE_REQUEST = "getCertsForChallenge";

    // BigInteger Value and BigIntegerValue array.
    public final static String SERIALNO = "serialNumber";
    public final static String SERIALNOS = "serialNumbers";

    // int value.
    public final static String REVOKE_REASON = "revokeReason";

    // this has a string value.
    public final static String HOLDINSTRCODE = "holdInstrCode";
    public final static String HOLDCALLISSUER = "holdCallIssuer";
    public final static String HOLDREJECT = "holdReject";

    // this has a Date value.
    public final static String INVALIDITYDATE = "InvalidityDate";

    // this has a CRLExtensions value.
    public final static String CRLEXTS = "CRLExts";

    // this has a String value - it is either null or set.
    public final static String DOGETCACHAIN = "doGetCAChain";

    // this has a CertificateChain value.
    public final static String CACERTCHAIN = "CACertChain";

    // this has a CRL value.
    public final static String CRL = "CRL";

    // this has a X509CertImpl value.
    public final static String CERTIFICATE = "certificate";

    // this is an array of EBaseException for service errors when
    // there's an error processing an array of something such as
    // certs to renew, certs to revoke, etc.
    public final static String SVCERRORS = "serviceErrors";

    // crl update status after a revocation.
    public final static String CRL_UPDATE_STATUS = "crlUpdateStatus";
    public final static String CRL_UPDATE_ERROR = "crlUpdateError";
}
