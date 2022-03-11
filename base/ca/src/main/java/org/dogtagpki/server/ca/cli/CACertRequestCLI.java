//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.cert.CertRequestInfo;

/**
 * @author Endi S. Dewata
 */
public class CACertRequestCLI extends CLI {

    public CACertRequestCLI(CLI parent) {
        super("request", "CA certificate request management commands", parent);

        addModule(new CACertRequestImportCLI(this));
    }

    public static void printCertRequestInfo(CertRequestInfo info) {

        System.out.println("  Request ID: " + info.getRequestID().toHexString());
        System.out.println("  Type: " + info.getRequestType());
        System.out.println("  Status: " + info.getRequestStatus());
        System.out.println("  Result: " + info.getOperationResult());

        String error = info.getErrorMessage();
        if (error != null) {
            System.out.println("  Reason: " + error);
        }

        if (info.getCertId() != null) {
            System.out.println("  Certificate ID: " + info.getCertId().toHexString());
        }
    }
}
