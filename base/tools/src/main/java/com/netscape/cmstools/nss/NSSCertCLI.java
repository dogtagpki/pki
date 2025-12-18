//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.nss;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.dogtagpki.cli.CLI;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Cert;

import com.netscape.certsrv.dbs.certdb.CertId;

public class NSSCertCLI extends CLI {

    public NSSCertCLI(NSSCLI nssCLI) {
        super("cert", "NSS certificate management commands", nssCLI);

        addModule(new NSSCertFindCLI(this));
        addModule(new NSSCertExportCLI(this));
        addModule(new NSSCertImportCLI(this));
        addModule(new NSSCertIssueCLI(this));
        addModule(new NSSCertModifyCLI(this));
        addModule(new NSSCertRequestCLI(this));
        addModule(new NSSCertShowCLI(this));
        addModule(new NSSCertRemoveCLI(this));
        addModule(new NSSCertVerifyCLI(this));
    }

    public static NSSCertInfo createCertInfo(X509Certificate cert) throws Exception {

        NSSCertInfo certInfo = new NSSCertInfo();

        certInfo.setNickname(cert.getNickname());
        certInfo.setSerialNumber(new CertId(cert.getSerialNumber()));

        certInfo.setSubjectDN(cert.getSubjectDN().toString());
        certInfo.setIssuerDN(cert.getIssuerDN().toString());

        PK11Cert pk11Cert = (PK11Cert) cert;

        certInfo.setNotBefore(pk11Cert.getNotBefore());
        certInfo.setNotAfter(pk11Cert.getNotAfter());

        certInfo.setTrustFlags(pk11Cert.getTrustFlags());

        return certInfo;
    }

    public static void printCertInfo(NSSCertInfo cert) throws Exception {
        try (StringWriter sb = new StringWriter();
                PrintWriter out = new PrintWriter(sb)) {
            printCertInfo(cert, out);
            System.out.print(sb);
            System.out.flush();
        }
    }

    public static void printCertInfo(NSSCertInfo cert, PrintWriter out) throws Exception {
        out.println("  Nickname: " + cert.getNickname());
        out.println("  Serial Number: " + cert.getSerialNumber().toHexString());
        out.println("  Subject DN: " + cert.getSubjectDN());
        out.println("  Issuer DN: " + cert.getIssuerDN());
        out.println("  Not Valid Before: " + cert.getNotBefore());
        out.println("  Not Valid After: " + cert.getNotAfter());
        out.println("  Trust Flags: " + cert.getTrustFlags());
    }
}
