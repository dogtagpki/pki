//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import org.dogtagpki.cli.CLI;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Cert;

import com.netscape.certsrv.dbs.certdb.CertId;

public class NSSCertCLI extends CLI {

    public NSSCertCLI(NSSCLI nssCLI) {
        super("cert", "NSS certificate management commands", nssCLI);

        addModule(new NSSCertExportCLI(this));
        addModule(new NSSCertImportCLI(this));
        addModule(new NSSCertIssueCLI(this));
        addModule(new NSSCertRequestCLI(this));
        addModule(new NSSCertShowCLI(this));
    }

    public static void printCertInfo(X509Certificate cert) throws Exception {

        System.out.println("  Nickname: " + cert.getNickname());

        CertId serialNumber = new CertId(cert.getSerialNumber());
        System.out.println("  Serial Number: " + serialNumber.toHexString());

        System.out.println("  Subject DN: " + cert.getSubjectDN());
        System.out.println("  Issuer DN: " + cert.getIssuerDN());

        PK11Cert pk11Cert = (PK11Cert) cert;
        System.out.println("  Not Valid Before: " + pk11Cert.getNotBefore());
        System.out.println("  Not Valid After: " + pk11Cert.getNotAfter());

        System.out.println("  Trust Attributes: " + pk11Cert.getTrustFlags());
    }
}
