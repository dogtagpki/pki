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

import java.io.*;
import java.util.*;

/**
 * An interface represents authentiator.
 *
 * @author thomask
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class BasicAuthenticator implements IAuthenticator {

	private String mUserid = null;
	private String mPassword = null;

	public BasicAuthenticator(String userid, String password) {
		mUserid = userid;
		mPassword = password;
	}

	public String getUserid() {
		return mUserid;
	}
	
	public String getPassword() {
		return mPassword;
	}

	public void setUserId(String userid) {
		mUserid = userid;
	}
	
	public void setPassword(String password) {
		mPassword = password;
	}
}
