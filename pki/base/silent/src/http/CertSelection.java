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

import java.io.*;
import java.net.*;
import java.nio.*;
import java.util.*;

import org.mozilla.jss.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.PK11Token;


public class CertSelection implements SSLClientCertificateSelectionCallback
{

	// make the select() call to use this client cert
	public static String client_cert = null;

	public void setClientCert(String nickname)
	{
		client_cert = nickname;
	}

	public String select(Vector nicknames)
	{

		// when this method is called by SSLSocket we get a vector
		// of nicknames to select similar to the way the browser presents
		// the list.

		// We will just use the one thats set by setClientCert()

		return client_cert;
	}

}; // end class
