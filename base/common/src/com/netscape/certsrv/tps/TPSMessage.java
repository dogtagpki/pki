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
package com.netscape.certsrv.tps;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSMessage {

    Map<String, String> map = new LinkedHashMap<String, String>();

    public TPSMessage() {
    }

    public TPSMessage(String message) {
        decode(message);
    }

    public TPSMessage(Map<String, String> map) {
        this.map.putAll(map);
    }

    public void put(String key, String value) {
        map.put(key, value);
    }

    public void put(String key, Integer value) {
        map.put(key, value.toString());
    }

    public void put(String key, byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes) {
            sb.append("%");
            sb.append(String.format("%02X", b));
        }

        map.put(key, sb.toString());
    }

    public void decode(String message) {

        for (String nvp : message.split("&")) {
            String[] s = nvp.split("=");

            String key = s[0];
            String value = s[1];

            // skip message size
            if (key.equals("s")) continue;

            map.put(key, value);
        }
    }

    public String encode() {

        StringBuilder sb = new StringBuilder();

        // encode message type
        String type = map.get("msg_type");
        sb.append("msg_type=" + type);

        // encode other parameters
        for (String key : map.keySet()) {

            if (key.equals("msg_type")) continue;

            String value = map.get(key);
            sb.append("&" + key + "=" + value);
        }

        String message = sb.toString();

        // encode message_size
        return "s=" + message.length() + "&" + message;
    }

    public String toString() {
        return map.toString();
    }
}
