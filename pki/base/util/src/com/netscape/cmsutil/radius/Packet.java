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
package com.netscape.cmsutil.radius;


import java.util.*;
import java.math.*;
import java.security.*;
import java.net.*;
import java.io.*;


public abstract class Packet {
    public static final int ACCESS_REQUEST = 1; 
    public static final int ACCESS_ACCEPT = 2; 
    public static final int ACCESS_REJECT = 3; 
    // public static final int ACCOUNTING_REQUEST = 4; 
    // public static final int ACCOUNTING_RESPONSE = 5; 
    public static final int ACCESS_CHALLENGE = 11;
    public static final int RESERVED = 255; 

    protected int _c = 0;
    protected short _id = 0;
    protected Authenticator _auth = null;
    protected AttributeSet _attrs = new AttributeSet();

    public Packet() {
    }

    public Packet(int c, short id, Authenticator auth) {
        _c = c;
        _id = id;
        _auth = auth;
    }

    public int getCode() {
        return _c;
    }

    public short getIdentifier() {
        return _id;
    }

    public Authenticator getAuthenticator() {
        return _auth;
    }

    public void addAttribute(Attribute attr) {
        _attrs.addAttribute(attr);
    }

    public AttributeSet getAttributeSet() {
        return _attrs;
    }

    public Attribute getAttributeAt(int pos) {
        return _attrs.getAttributeAt(pos);
    }

    public String toString() {
        return "Packet [code=" + _c + ",id=" + (_id & 0xFF) + "]";
    }
}
