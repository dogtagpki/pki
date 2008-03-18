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
package com.netscape.certsrv.dbs.keydb;


import java.util.*;
import java.io.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;


/**
 * A class represents key state. This object is to
 * encapsulate the life cycle of a key.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public final class KeyState implements Serializable {

    private int mStateCode;

    /**
     * Constructs a key state.
     */
    private KeyState(int code) {
        mStateCode = code;
    }
	
    /**
     * Request state.
     */
    public final static KeyState ANY = new  KeyState(-1);
    public final static KeyState VALID = new KeyState(0);
    public final static KeyState INVALID = new KeyState(1);
		
    /**
     * Checks if the given object equals to this object.
     *
     * @param other object to be compared
     * @return true if both objects are the same
     */
    public boolean equals(Object other) {
        if (this == other) 
            return true;
        else if (other instanceof KeyState)
            return ((KeyState) other).mStateCode == mStateCode;
        else 
            return false;
    }

    /**
     * Returns the hash code.
     *
     * @return hash code
     */
    public int hashCode() {
        return mStateCode;
    }
	
    /**
     * Return the string-representation of this object.
     *
     * @return string value
     */
    public String toString() {
        if (mStateCode == -1) return "ANY";
        if (mStateCode == 0) return "VALID";
        if (mStateCode == 1) return "INVAILD";
        return "[UNDEFINED]";
		
    }

    /**
     * Converts a string into a key state object.
     *
     * @param state state in string-representation
     * @return key state object
     */
    public static KeyState toKeyState(String state) {
        if (state.equalsIgnoreCase("ANY")) return ANY; 
        if (state.equalsIgnoreCase("VALID")) return VALID; 
        if (state.equalsIgnoreCase("INVALID")) return INVALID; 
        return null;
    }
}

