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

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * The KeyIdAdapter class provides custom marshaling for KeyId.
 *
 * @author Endi S. Dewata
 * @version $Revision$ $Date$
 */
public class KeyIdAdapter extends XmlAdapter<String, KeyId> {

    public KeyId unmarshal(String value) throws Exception {
        return new KeyId(value);
    }

    public String marshal(KeyId value) throws Exception {
        return value.toString();
    }
}
