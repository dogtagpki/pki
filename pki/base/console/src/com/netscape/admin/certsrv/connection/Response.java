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
package com.netscape.admin.certsrv.connection;

import java.net.*;
import java.io.*;
import java.util.*;

/**
 * Response - now use vector to maintain the oredering
 *
 * @author kanda
 * @author thomask
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class Response {
	boolean debug = true;
	boolean test = true;
	boolean testsuccess = true; // test success condition?

	public static final int SUCCESS = 0;
    public static final int RESTART = -1;

	private int mRetcode;
	private String mErrorMsg;
	
	//internal structure is changed to vector to maintain
	//the ordering
	
	private Vector mName = new Vector();
	private Vector mValue = new Vector();

	public Response() {
	// for testing only

	}

	public Response(byte[] resp) throws IOException {
		ByteArrayInputStream bis = new ByteArrayInputStream(resp);
		DataInputStream dis = new DataInputStream(bis);
		mRetcode = dis.readInt();
		byte[] mContents = null;

	if (debug)
		//System.out.println("===in Response===\n");

		if ((mRetcode != SUCCESS) && (mRetcode != RESTART)) {
			mErrorMsg = dis.readUTF();
		} else {
			if (resp.length > 4) {
				mContents = new byte[resp.length - 4];
				dis.read(mContents);
			}
		}
		if (mContents != null) {
			String resultStr = new String(mContents);
			StringTokenizer st = new StringTokenizer(resultStr, 
				"&");
			while (st.hasMoreTokens()) {
				String p = st.nextToken();
				int i = p.indexOf("=");
				if (i == -1) {
					return;
				}
				String t = URLdecode(p.substring(0, i));
				String v = URLdecode(p.substring(i + 1));
				mName.addElement(t);
				mValue.addElement(v);
			}
		}
	}

	public int getReturnCode() { 
		return mRetcode; 
	}

	public String getErrorMessage() { 
		return mErrorMsg; 
	}

	/**
	 * URL decodes the given string.
	 */
	public String URLdecode(String s) {
		if (s == null)
			return null;
		ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
		for (int i = 0; i < s.length(); i++) {
			int c = (int) s.charAt(i);
			if (c == '+') {
				out.write(' ');
			} else if (c == '%') {
				int c1 = Character.digit(s.charAt(++i), 16);
				int c2 = Character.digit(s.charAt(++i), 16);
				out.write((char) (c1 * 16 + c2));
			} else {
				out.write(c);
			}
		} // end for
		return out.toString();
	}

	public Enumeration getNames() {
		return mName.elements();
	}

	public String get(String name) {
	    int i = mName.indexOf(name);
	    String value;
	    try {
		    value =  (String) mValue.elementAt(i);
		} catch (ArrayIndexOutOfBoundsException e) {
		    value = "";    
		}
		return value;
	}
}
