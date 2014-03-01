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

public class StatusUpdateRequest extends TPSMessage {
    public StatusUpdateRequest(int status, String info) {

        put(MSG_TYPE_NAME, msgTypeToInt(MsgType.MSG_STATUS_UPDATE_REQUEST));
        put(STATUS_NAME, status);
        put(INFO_NAME, info);

    }

    public static void main(String[] args) {

        StatusUpdateRequest req = new StatusUpdateRequest(10, "PROGRESS_APPLET_BLOCK");
        System.out.println(req.encode());

    }

}
