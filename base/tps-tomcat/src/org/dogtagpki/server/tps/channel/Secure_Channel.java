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
package org.dogtagpki.server.tps.channel;

public class Secure_Channel {

   public enum SecurityLevel {
        SECURE_MSG_ANY ,
        SECURE_MSG_MAC ,
        SECURE_MSG_NONE , // not yet supported
        SECURE_MSG_MAC_ENC
    }

    public Secure_Channel() {

    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
