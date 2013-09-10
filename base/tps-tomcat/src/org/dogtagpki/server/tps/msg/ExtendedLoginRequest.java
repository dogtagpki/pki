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
package org.dogtagpki.server.tps.msg;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.dogtagpki.server.tps.main.Util;

public class ExtendedLoginRequest extends TPSMessage {

   public ExtendedLoginRequest(int invalid_pw, int blocked, Set<String> params, String title, String description) {


        put(INVALID_PWD_NAME, invalid_pw);
        put(BLOCKED_NAME,blocked);
        put(MSG_TYPE_NAME, msgTypeToInt(Msg_Type.MSG_EXTENDED_LOGIN_REQUEST));
        this.params = params;

    }

    @Override

    public String encode() {

        if(!params.isEmpty()) {

            int i = 0;
            for(Iterator<String> iter = params.iterator(); iter.hasNext(); ) {

                String curParam = null;

                try {
                    curParam  = Util.URIEncode(iter.next());
                } catch (UnsupportedEncodingException e) {
                    curParam = null;
                }

                if(curParam  != null && curParam.length() > 0) {

                    String name = "&" + PARAMETER_NAME + Integer.toString(i++);
                    String value = curParam;

                    put(name, value);

                }

            }

        }

        return  super.encode();

    }

    private Set<String> params;

    public static void main(String[] args) {

        final String title = "LDAP Authentication";
        final String description = "This authenticates user against the LDAP directory.";

        Set<String> params = new HashSet<String>();

        params.add("id=UID&name=LDAP User ID&desc=LDAP User ID&type=string&option=");
        params.add("id=PASSWORD&name=LDAP Password&desc=LDAP Password&type=password&option=");


        ExtendedLoginRequest ext_login_req = new ExtendedLoginRequest(0, 0, params, title, description);

        System.out.println(ext_login_req.encode());

    }

}
