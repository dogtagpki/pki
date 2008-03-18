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
package com.netscape.admin.certsrv.security;

/**
 * This interface contains all the internal string constants for each
 * cipher encrytion methods.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
public interface ICipherConstants {
    // export ssl2 cipher
    /**SSL2 Export - RC4 with 40 bit encryption and MD5 message authentication*/
    public final static String RC4EXPORT = "rc4export";
    /**SSL2 Export - RC2 with 40 bit encryption and MD5 message authentication*/
    public final static String RC2EXPORT = "rc2export";

    // domestic ssl2 cipher
    /**SSL2 Domestic - RC4 with 128 bit encryption and MD5 message authentication*/
    public final static String RC4 = "rc4";
    /**SSL2 Domestic - RC2 with 128 bit encryption and MD5 message authentication*/
    public final static String RC2 = "rc2";
    /**SSL2 Domestic - DES with 56 bit encryption and MD5 message authentication*/
    public final static String DES = "des";
    /**SSL2 Domestic - Triple DES with 168 bit encryption and MD5 message authentication*/
    public final static String DES3 = "desede3";

    // export ssl3 cipher
    /**SSL3 Export - RC4 with 40 bit encryption and MD5 message authentication*/
    public final static String RSA_RC4_40_MD5 = "rsa_rc4_40_md5";
    /**SSL3 Export - RC2 with 40 bit encryption and MD5 message authentication*/
    public final static String RSA_RC2_40_MD5 = "rsa_rc2_40_md5";
    /**SSL3 Export - No encryption, only MD5 message authentication*/
    public final static String RSA_NULL_MD5 = "rsa_null_md5";
    /**SSL3 Export - TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    public final static String TLS_RSA_DES_SHA = "tls_rsa_export1024_with_des_cbc_sha";
    /**SSL3 Export - TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    public final static String TLS_RSA_RC4_SHA = "tls_rsa_export1024_with_rc4_56_sha";

    // domestic ssl3 cipher
    /**SSL3 Domestic - DES with 56 bit encryption and SHA message authentication*/
    public final static String RSA_DES_SHA = "rsa_des_sha";
    /**SSL3 Domestic - RC4 with 128 bit encryption and MD5 message authentication*/
    public final static String RSA_RC4_128_MD5 = "rsa_rc4_128_md5";
    /**SSL3 Domestic - Triple DES with 168 bit encryption and SHA message authentication*/
    public final static String RSA_3DES_SHA = "rsa_3des_sha";

    // fortezza ciphers
    /**SSL3 Domestic - Fortezza with 80 bit encryption and SHA message authentication */
    public final static String FORTEZZA = "fortezza";
    /**SSL3 Domestic - RC4 with 128 bit encryption and Fortezza/SHA message authentication */
    public final static String FORTEZZA_RC4_128_SHA = "fortezza_rc4_128_sha";
    /**SSL3 Domestic - No encryption, only Fortezza and SHA message authentication */
    public final static String FORTEZZA_NULL = "fortezza_null";

    // FIPS ciphers
    public final static String RSA_FIPS_DES_SHA = "rsa_fips_des_sha";
    public final static String RSA_FIPS_3DES_SHA = "rsa_fips_3des_sha";
}
