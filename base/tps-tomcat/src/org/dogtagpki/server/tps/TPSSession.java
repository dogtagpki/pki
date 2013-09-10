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
package org.dogtagpki.server.tps;

import java.io.IOException;

import org.dogtagpki.server.tps.msg.BeginOp;
import org.dogtagpki.server.tps.msg.EndOp;
import org.dogtagpki.server.tps.msg.TPSMessage;
import org.dogtagpki.server.tps.processor.TPS_Format_Processor;
import org.dogtagpki.server.tps.processor.TPS_Processor;
import org.dogtagpki.server.tps.processor.TPS_Processor.TPS_Status;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class TPSSession {

    public TPSSession(TPSConnection conn) {

        CMS.debug("TPSSession constructor conn: " + conn);
        connection = conn;
    }

    public TPSConnection getConnection() {
        return connection;
    }

    public TPSMessage ReadMsg() throws IOException {
        TPSMessage message = null;

        if (connection != null) {
            CMS.debug("TPSSession.process() about to call read on connection : " + connection);

            try {
                message = connection.read();
                CMS.debug("TPSSession.process() created message " + message);

            } catch (Exception e) {
                //Catch here so we can log
                CMS.debug("Exception reading from the client: " + e.toString());
                throw new IOException(e.toString());
            }
        } else {
            throw new IOException("No connection available in TPSSession instance!");
        }

        return message;
    }

    public void WriteMsg(TPSMessage msg) throws IOException {

        if (connection != null) {

            try {
                connection.write(msg);
            } catch (Exception e) {
                //Catch here so we can log
                CMS.debug("Exception reading from the client: " + e.toString());
                throw new IOException(e.toString());
            }

        } else {
            throw new IOException("No conneciton available in TPSSession instance!");
        }
    }

    public void process() throws IOException, EBaseException {
        TPS_Processor.TPS_Status status = TPS_Status.STATUS_ERROR_BAD_STATUS;
        CMS.debug("In TPSSession.process()");

        TPSMessage firstMsg = ReadMsg();

        if (firstMsg == null) {
            throw new IOException("Can't create first TPSMessage!");
        }

        TPSMessage.Msg_Type msg_type = firstMsg.GetType();
        TPSMessage.Op_Type op_type = firstMsg.getOpType();

        if (msg_type != TPSMessage.Msg_Type.MSG_BEGIN_OP) {
            throw new IOException("Wong first message type read in TPSSession.process!");
        }

        switch (op_type) {
        case OP_FORMAT:

            TPS_Format_Processor processor = new TPS_Format_Processor();
            BeginOp beginOp = (BeginOp) firstMsg;
            status = processor.Process(this, beginOp);

        case OP_ENROLL:
            break;
        case OP_RENEW:
            break;
        case OP_RESET_PIN:
            break;
        case OP_UNBLOCK:
            break;
        case OP_UNDEFINED:
            break;
        default:
            break;

        }

        int result = EndOp.RESULT_ERROR;

        if (status == TPS_Processor.TPS_Status.STATUS_NO_ERROR) {
            result = EndOp.RESULT_GOOD;
        }

        EndOp endOp = new EndOp(firstMsg.getOpType(), result, status);

        WriteMsg(endOp);

        CMS.debug("TPSSession.process: leaving: result: " + result + " status: " + status);

    }

    private TPSConnection connection;

}
