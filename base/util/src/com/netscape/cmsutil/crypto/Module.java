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
package com.netscape.cmsutil.crypto;

import org.mozilla.jss.crypto.*;

import java.util.*;

public class Module {
    // Common Name is the name given when module is added
    private String mCommonName = "";
    // User friendly name is the name to be displayed on panel
    private String mUserFriendlyName = "";
    private String mImagePath = "";
    // a Vector of Tokens
    private Vector mTokens = null;
    private boolean mFound = false;

    public Module (String name, String printName) {
	mCommonName = name;
	mUserFriendlyName = printName;
	mTokens = new Vector();
    }

    public Module (String name, String printName, String image) {
	mCommonName = name;
	mUserFriendlyName = printName;
	mImagePath = image;
	mTokens = new Vector();
    }

    public void addToken(CryptoToken t) {
	Token token = new Token(t);
	mTokens.addElement(token);
    }

    public String getCommonName() {
	return mCommonName;
    }

    public String getUserFriendlyName() {
	return mUserFriendlyName;
    }

    public String getImagePath() {
	return mImagePath;
    }

    public boolean isFound() {
        return mFound;
    }

    public void setFound(boolean isFound) {
        mFound = isFound;
    }

    public Vector getTokens() {
	return mTokens;
    }
}
