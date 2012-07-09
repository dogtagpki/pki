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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class UserPasswordAttribute extends Attribute {
    private Authenticator _ra = null;
    private String _secret = null;
    private String _password = null;

    public UserPasswordAttribute(byte value[]) {
        //
    }

    public UserPasswordAttribute(Authenticator ra, String secret, String password) {
        super(USER_PASSWORD);
        _ra = ra;
        _secret = secret;
        _password = password;
    }

    public byte[] getValue() throws IOException {
        MessageDigest md5 = null;

        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e.getMessage());
        }
        md5.update(_secret.getBytes());
        md5.update(_ra.getData());
        byte sum[] = md5.digest();

        byte up[] = _password.getBytes();
        int oglen = (up.length / 16) + 1;
        byte ret[] = new byte[oglen * 16];

        for (int i = 0; i < ret.length; i++) {
            if ((i % 16) == 0) {
                md5.reset();
                md5.update(_secret.getBytes());
            }
            if (i < up.length) {
                ret[i] = (byte) (sum[i % 16] ^ up[i]);
            } else {
                ret[i] = sum[i % 16];
            }
            md5.update(ret[i]);
            if ((i % 16) == 15) {
                sum = md5.digest();
            }
        }
        return ret;
    }
}
