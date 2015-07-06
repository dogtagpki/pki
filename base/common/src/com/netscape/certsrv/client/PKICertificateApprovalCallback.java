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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Enumeration;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

public class PKICertificateApprovalCallback implements SSLCertificateApprovalCallback {

    public PKIClient client;

    public PKICertificateApprovalCallback(PKIClient client) {
        this.client = client;
    }

    // NOTE:  The following helper method defined as
    //        'public String displayReason(int reason)'
    //        should be moved into the JSS class called
    //        'org.mozilla.jss.ssl.SSLCertificateApprovalCallback'
    //        under its nested subclass called 'ValidityStatus'.

    // While all reason values should be unique, this method has been
    // written to return the name of the first defined reason that is
    // encountered which contains the requested value, or null if no
    // reason containing the requested value is encountered.
    public String displayReason(int reason) {

        for (Field f : ValidityStatus.class.getDeclaredFields()) {
            int mod = f.getModifiers();
            if (Modifier.isStatic(mod) &&
                Modifier.isPublic(mod) &&
                Modifier.isFinal(mod)) {
                try {
                    int value = f.getInt(null);
                    if (value == reason) {
                        return f.getName();
                    }
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
            }
        }

        return null;
    }

    public String getMessage(X509Certificate serverCert, int reason) {

        if (reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {
            return "BAD_CERT_DOMAIN encountered on '"+serverCert.getSubjectDN()+"' indicates a common-name mismatch";
        }

        if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER) {
            return "UNTRUSTED ISSUER encountered on '" +
                    serverCert.getSubjectDN() + "' indicates a non-trusted CA cert '" +
                    serverCert.getIssuerDN() + "'";
        }

        if (reason == SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID) {
            return "CA_CERT_INVALID encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
        }

        String reasonName = displayReason(reason);
        if (reasonName != null) {
            return reasonName+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
        }

        return "Unknown/undefined reason "+reason+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
    }

    public boolean handleUntrustedIssuer(X509Certificate serverCert) {
        try {
            System.out.print("Import CA certificate (Y/n)? ");

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine().trim();

            if (!line.equals("") && !line.equalsIgnoreCase("Y"))
                return false;

            String caServerURI = "http://" + client.getConfig().getServerURI().getHost() + ":8080/ca";

            System.out.print("CA server URI [" + caServerURI + "]: ");
            System.out.flush();

            line = reader.readLine().trim();
            if (!line.equals("")) {
                caServerURI = line;
            }

            if (client.verbose) System.out.println("Downloading CA certificate chain from " + caServerURI + ".");
            byte[] bytes = client.downloadCACertChain(caServerURI);

            if (client.verbose) System.out.println("Importing CA certificate chain.");
            client.importCACertPackage(bytes);

            if (client.verbose) System.out.println("Imported CA certificate.");
            return true;

        } catch (Exception e) {
            System.err.println("ERROR: "+e);
            return false;
        }
    }

    // Callback to approve or deny returned SSL server cert.
    // Right now, simply approve the cert.
    public boolean approve(X509Certificate serverCert,
            SSLCertificateApprovalCallback.ValidityStatus status) {

        boolean approval = true;

        if (client.verbose) System.out.println("Server certificate: "+serverCert.getSubjectDN());

        SSLCertificateApprovalCallback.ValidityItem item;

        // If there are no items in the Enumeration returned by
        // getReasons(), you can assume that the certificate is
        // trustworthy, and return true to allow the connection to
        // continue, or you can continue to make further tests of
        // your own to determine trustworthiness.
        Enumeration<?> errors = status.getReasons();

        while (errors.hasMoreElements()) {
            item = (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();
            int reason = item.getReason();

            if (client.isRejected(reason)) {
                if (!client.statuses.contains(reason))
                    System.err.println("ERROR: " + getMessage(serverCert, reason));
                approval = false;

            } else if (client.isIgnored(reason)) {
                // Ignore validity status

            } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER) {
                // Issue a WARNING, but allow this process
                // to continue since we haven't installed a trusted CA
                // cert for this operation.
                if (!client.statuses.contains(reason)) {
                    System.err.println("WARNING: " + getMessage(serverCert, reason));
                    handleUntrustedIssuer(serverCert);
                }

            } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {
                // Issue a WARNING, but allow this process to continue on
                // common-name mismatches.
                if (!client.statuses.contains(reason))
                    System.err.println("WARNING: " + getMessage(serverCert, reason));

            } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID) {
                // Set approval false to deny this
                // certificate so that the connection is terminated.
                // (Expect an IOException on the outstanding
                //  read()/write() on the socket).
                if (!client.statuses.contains(reason))
                    System.err.println("ERROR: " + getMessage(serverCert, reason));
                approval = false;

            } else {
                // Set approval false to deny this certificate so that
                // the connection is terminated. (Expect an IOException
                // on the outstanding read()/write() on the socket).
                if (!client.statuses.contains(reason))
                    System.err.println("ERROR: " + getMessage(serverCert, reason));
                approval = false;
            }

            client.statuses.add(reason);
        }

        return approval;
    }
}
