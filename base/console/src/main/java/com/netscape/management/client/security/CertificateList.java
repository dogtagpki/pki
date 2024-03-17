/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.security;

import java.util.*;

class CertificateList {

    final static int SERVER = 1;
    final static int CA     = 2;
    final static int CRL    = 4;

    Vector serverCerts, CACerts, CRLCerts;
    boolean needInit = false;

    public CertificateList(String unparsedCertList) {

        setCertList(new Parser(unparsedCertList));
    }

    public Vector getServerCerts() {
        return serverCerts;
    }

    public Vector getCACerts() {
        return CACerts;
    }

    public Vector getCRLCerts() {
        return CRLCerts;
    }

    public Vector getCerts() {
    	Vector certs = new Vector();
	certs.addAll(CACerts);
	certs.addAll(serverCerts);
	certs.addAll(CRLCerts);
	return certs;
    }

    public boolean needInitInternalToken() {
	return needInit;
    }

    void setCertList(Parser tokens) {
        CACerts     = new Vector();
        serverCerts = new Vector();
        CRLCerts    = new Vector();


        String typeKeyword;
        while (tokens.hasMoreElement()) {
            typeKeyword = tokens.nextToken();

            if (typeKeyword.equals("<SERVER>")) {
                serverCerts.addElement(tokens.getTokenObject/*Cert*/(typeKeyword));
            } else if (typeKeyword.equals("<CA>")) {
                CACerts.addElement(tokens.getTokenObject/*Cert*/(typeKeyword));
            } else if (typeKeyword.equals("<CRL>") || typeKeyword.equals("<CKL>")) {
                CRLCerts.addElement(tokens.getTokenObject/*Cert*/(typeKeyword));
            } else if (typeKeyword.equals("<NEEDINIT_INTERNAL>")) {
		needInit = tokens.nextToken().equals("TRUE");
		//get </NEEDINIT_INTERNAL>
		tokens.nextToken();
	    }
        }
    }
}


