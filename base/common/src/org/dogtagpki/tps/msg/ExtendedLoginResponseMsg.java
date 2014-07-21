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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.tps.msg;

import java.util.HashMap;
import java.util.Map;

public class ExtendedLoginResponseMsg extends TPSMessage {

    private Map<String, String> authParams;

    public ExtendedLoginResponseMsg(String msg) {

        super(msg);

        authParams = new HashMap<String, String>();
        //ToDo process the actual params
    }

    public ExtendedLoginResponseMsg(OpType theOp, String uid, String password, Map<String, String> theExtensions) {

        put(OPERATION_TYPE_NAME, opTypeToInt(theOp));
        put(MSG_TYPE_NAME, msgTypeToInt(MsgType.MSG_EXTENDED_LOGIN_RESPONSE));
        authParams = theExtensions;
        put(UID_NAME, uid);
        put(PASSWORD_NAME, password);

    }

    public static void main(String[] args) {

    }

    public Map<String, String> getAuthParams() {
        return authParams;
    }

}
