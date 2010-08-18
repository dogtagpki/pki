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
package com.netscape.cmstools;


import java.io.*;
import java.net.*;
import netscape.security.x509.*;
import netscape.security.util.*;


/**
 * This program generates an issuer alternative name extension
 * in base-64 encoding. The encoding output can be used with 
 * the configuration wizard.
 *
 * Usage:
 *  GenIssuerAltNameExt \
 *    <general_type0> <general_name0> ... <general_typeN> <general_nameN>
 *
 *  where,
 *    <general_type> can be one of the following string:
 *      DNSName 
 *      EDIPartyName
 *      IPAddressName
 *      URIName
 *      RFC822Name
 *      OIDName
 *      X500Name
 *    <general_name> is string
 *
 * @version $Revision$, $Date$
 */
public class GenIssuerAltNameExt {

    public static void main(String args[]) {
        try {
            if ((args.length == 0) || (args.length % 2 != 0)) {
                doUsage();
                System.exit(0);
            }
            GeneralNames gns = new GeneralNames();

            for (int i = 0; i < args.length; i += 2) {
                GeneralNameInterface gni = 
                    buildGeneralNameInterface(
                        args[i], args[i + 1]);

                gns.addElement(gni);
            }

            IssuerAlternativeNameExtension sane = 
                new IssuerAlternativeNameExtension(gns);	

            output(sane);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    public static void output(IssuerAlternativeNameExtension ext)
        throws Exception {
        ByteArrayOutputStream os = new ByteArrayOutputStream(); 

        ext.encode(os);

        System.out.println(
            com.netscape.osutil.OSUtil.BtoA(os.toByteArray())
        );
    }

    public static void doUsage() {
        System.out.println();
        System.out.println("Usage:  GenIssuerAltNameExt <general_type0> <general_name0> ... <general_typeN> <general_nameN>");
        System.out.println("where,");
        System.out.println("<general_type> can be one of the following string:");
        System.out.println("\tDNSName");
        System.out.println("\tEDIPartyName");
        System.out.println("\tIPAddressName");
        System.out.println("\tURIName");
        System.out.println("\tRFC822Name");
        System.out.println("\tOIDName");
        System.out.println("\tX500Name");
        System.out.println("<general_name> is a string");
    }

    public static GeneralNameInterface buildGeneralNameInterface(
        String type, String value) throws Exception {
        if (type.equals("DNSName")) {
            return new DNSName(value);
        } else if (type.equals("EDIPartyName")) {
            return new DNSName(value);
        } else if (type.equals("IPAddressName")) {
            InetAddress addr = InetAddress.getByName(value);

            return new IPAddressName(addr.getAddress());
        } else if (type.equals("URIName")) {
            return new URIName(value);
        } else if (type.equals("OIDName")) {
            return new OIDName(new ObjectIdentifier(value));
        } else if (type.equals("RFC822Name")) {
            return new RFC822Name(value);
        } else if (type.equals("X500Name")) {
            return new X500Name(value);
        } else {
            System.out.println("Error: unknown general_type " + 
                type);
            doUsage();
            System.exit(0);
            return null;
        }
    }
}
