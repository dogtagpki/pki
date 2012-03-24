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
package com.netscape.certsrv.common;


import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;


/**
 * A class represents a name value pair. A name value
 * pair consists of a name and a value.
 *
 * @version $Revision$, $Date$
 */
public class NameValuePair {

    private String mName = null;
    private String mValue = null;

    /**
     * Constructs value pair object.
     *
     * @param name name
     * @param value value
     */
    public NameValuePair(String name, String value) {
        mName = name;
        mValue = value;
    }

    /**
     * Retrieves the name.
     *
     * @return name
     */
    public String getName() {
        return mName;
    }

    /**
     * Retrieves the value.
     *
     * @return value
     */
    public String getValue() {
        return mValue;
    }
	
    /**
     * Sets the value
     *
     * @param value value
     */
    public void setValue(String value) {
        mValue = value;
    }
}    
