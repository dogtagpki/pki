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

import org.dogtagpki.server.tps.processor.TPSProcessor;


public class EndOp extends TPSMessage {

    public static final int  RESULT_GOOD = 0;
    public static final int  RESULT_ERROR = 1;


    public EndOp(OpType theOp, int result, TPSProcessor.TPS_Status message) {
        put(MSG_TYPE_NAME, msgTypeToInt(MsgType.MSG_END_OP));
        put(OPERATION_TYPE_NAME, opTypeToInt(theOp));
        put(RESULT_NAME, result);
        put(MESSAGE_NAME, TPSProcessor.statusToInt(message));
    }

    public static void main(String[] args) {

        EndOp end_msg = new EndOp(OpType.OP_FORMAT,0,TPSProcessor.TPS_Status.STATUS_NO_ERROR);
        System.out.println(end_msg.encode());


    }

}
