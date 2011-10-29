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


public class RequestAuthenticator extends Authenticator {
    private byte _ra[] = null;

    public RequestAuthenticator(SecureRandom rand, String secret) 
        throws NoSuchAlgorithmException {
        byte[] authenticator = new byte[16];

        rand.nextBytes(authenticator);

        MessageDigest md5 = MessageDigest.getInstance("MD5");

        md5.update(authenticator);
        md5.update(secret.getBytes());
        _ra = md5.digest();
    }

    public byte[] getData() throws IOException {
        return _ra;
    }
}
