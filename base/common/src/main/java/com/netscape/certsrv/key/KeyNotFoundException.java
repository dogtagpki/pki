package com.netscape.certsrv.key;

//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2007 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.dbs.keydb.KeyId;

public class KeyNotFoundException extends ResourceNotFoundException {

    private static final long serialVersionUID = -4688477890485145493L;

    public KeyId keyID;

    public KeyNotFoundException(KeyId keyId) {
        this(keyId, "Key ID " + keyId.toHexString() + " not found");
    }

    public KeyNotFoundException(KeyId keyId, String message) {
        super(message);
        this.keyID = keyId;
    }

    public KeyNotFoundException(KeyId keyId, String message, Throwable cause) {
        super(message, cause);
        this.keyID = keyId;
    }

    public KeyNotFoundException(Data data) {
        super(data);
        keyID = new KeyId(data.getAttribute("KeyId"));
    }

    public Data getData() {
        Data data = super.getData();
        data.setAttribute("KeyId", keyID.toString());
        return data;
    }

    public KeyId getKeyId() {
        return keyID;
    }

    public void setRequestId(KeyId KeyId) {
        this.keyID = KeyId;
    }
}
