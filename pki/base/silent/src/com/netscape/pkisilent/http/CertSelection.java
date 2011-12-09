package com.netscape.pkisilent.http;
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

import java.util.Vector;

import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;


public class CertSelection implements SSLClientCertificateSelectionCallback
{

	// make the select() call to use this client cert
	public static String client_cert = null;

	public void setClientCert(String nickname)
	{
		client_cert = nickname;
	}

	public String select(@SuppressWarnings("rawtypes") Vector nicknames)
	{

		// when this method is called by SSLSocket we get a vector
		// of nicknames to select similar to the way the browser presents
		// the list.

		// We will just use the one thats set by setClientCert()

		return client_cert;
	}

}; // end class
