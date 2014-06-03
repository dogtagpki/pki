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

import java.util.Map;

import com.netscape.certsrv.apps.CMS;

public class BeginOpMsg extends TPSMessage {

    private Map<String, String> extensions;

    public BeginOpMsg(OpType theOp, Map<String, String> theExtensions) {

        CMS.debug("BeingOp op: " + theOp + " extensions: " + theExtensions);
        put(OPERATION_TYPE_NAME, opTypeToInt(theOp));
        put(MSG_TYPE_NAME, msgTypeToInt(MsgType.MSG_BEGIN_OP));
        extensions = theExtensions;

    }

    public OpType getOpType() {

        int opTypeInt = getInt(OPERATION_TYPE_NAME);
        return intToOpType(opTypeInt);
    }

    public Map<String, String> getExtensions() {
        return extensions;
    }

    public String getExtension(String extName) {

        String result = null;

        if (extName == null)
            return result;

        return extensions.get(extName);

    }

}
