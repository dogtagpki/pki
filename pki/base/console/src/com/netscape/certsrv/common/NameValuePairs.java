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
 * A class represents an ordered list of name 
 * value pairs.
 *
 * @author thomask
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class NameValuePairs {

    private Vector mPairs = new Vector();

    // an index to speed up searching
    // The key is the name.  The element is the NameValuePair.
    private Hashtable index = new Hashtable();

    /**
     * Constructs name value pairs.
     */	 
    public NameValuePairs() {
    }

    /**
     * Adds a name value pair into this set.
     * if the name already exist, the value will
     * be replaced.
     */
    public void add(String name, String value) {
        NameValuePair pair = getPair(name);

        if (pair == null) {
            pair = new NameValuePair(name, value);
            mPairs.addElement(pair);
            index.put(name, pair);
        } else {
            pair.setValue(value);
        }
    }

    /**
     * Retrieves name value pair from this set.
     */
    public NameValuePair getPair(String name) {
        return (NameValuePair) index.get(name);
    }

    /**
     * Returns number of pairs in this set.
     */
    public int size() {
        return mPairs.size();
    }

    /**
     * Retrieves name value pairs in specific position.
     */
    public NameValuePair elementAt(int pos) {
        return (NameValuePair) mPairs.elementAt(pos);
    }

    /**
     * Removes all name value pairs in this set.
     */
    public void removeAllPairs() {
        mPairs.removeAllElements();
        index.clear();
    }

    /**
     * Retrieves value of the name value pairs that matches
     * the given name.
     */
    public String getValue(String name) {
        NameValuePair p = getPair(name);

        if (p != null) {
            return p.getValue();
        }
        return null;
    }

    /**
     * Retrieves a list of names.
     */
    public Enumeration getNames() {
        Vector v = new Vector();
        int size = mPairs.size(); 

        for (int i = 0; i < size; i++) { 
            NameValuePair p = (NameValuePair) mPairs.elementAt(i);

            v.addElement(p.getName());
        }
        //System.out.println("getNames: "+v.size());
        return v.elements();
    }
	
    /**
     * Show the content of this name value container as
     * string representation.
     *
     * @return string representation
     */
    public String toString() {
        StringBuffer buf = new StringBuffer();

        for (int i = 0; i < mPairs.size(); i++) {
            NameValuePair p = (NameValuePair) mPairs.elementAt(i);

            buf.append(p.getName() + "=" + p.getValue());
            buf.append("\n");
        }
        return buf.toString();
    }

    public static boolean parseInto(String s, NameValuePairs nvp) {
        StringTokenizer st = new StringTokenizer(s, "&");

        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            int i = t.indexOf("=");

            if (i == -1) {
                return false;
            }
            String n = t.substring(0, i);
            String v = t.substring(i + 1);

            nvp.add(n, v);
        }	
        return true;
    }

    public Enumeration elements() {
        return mPairs.elements();
    }
}    
