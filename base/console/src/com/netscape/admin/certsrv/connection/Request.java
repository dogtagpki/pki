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

import java.util.Enumeration;
import java.util.Vector;

/**
 * A class represents a connection to certificate server.
 *
 * @author thomask
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class Request {

	private String mPrefix = null;

	//internal structure is changed to vector to maintain
	//the ordering

	private Vector<String> mName = new Vector<>();
	private Vector<String> mValue = new Vector<>();

	public Request(String prefix) {
		mPrefix = prefix;
	}

	public String getPrefix() {
		return mPrefix;
	}

	public void set(String name, String value) {
		mName.addElement(name);
		mValue.addElement(value);
	}

	public String get(String name) {
	    int i = mName.indexOf(name);
	    try {
		    return mValue.elementAt(i);
		} catch (ArrayIndexOutOfBoundsException e) {
		    return "";
		}
	}

	public Enumeration<String> getElements() {
		return mName.elements();
	}

	public void removeAll() {
	    mName.removeAllElements();
	    mValue.removeAllElements();
	}
}
