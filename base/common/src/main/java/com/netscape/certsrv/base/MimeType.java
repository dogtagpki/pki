//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.base;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class MimeType {

    public static final String ANYTYPE = "*/*";

    public static final String TEXT_PLAIN = "text/plain";

    public static final String APPLICATION_JSON = "application/json";

    public static final String APPLICATION_XML = "application/xml";

    public static final String APPLICATION_OCTET_STREAM = "application/octet-stream";

    public static final String APPLICATION_PKIX_CERT = "application/pkix-cert";

    public static final String APPLICATION_PKCS7 = "application/pkcs7-mime";

    public static final String APPLICATION_PKCS10 = "application/pkcs10";

    public static final String APPLICATION_X_PEM_FILE = "application/x-pem-file";

    public static final String APPLICATION_PEM_CERTIFICATE_CHAIN = "application/pem-certificate-chain";

    public static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";

    private MimeType() {
    }
}
