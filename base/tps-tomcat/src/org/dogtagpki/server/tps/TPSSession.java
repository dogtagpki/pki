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

import org.dogtagpki.server.tps.processor.TPSProcessor;
import org.dogtagpki.tps.TPSConnection;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOp;
import org.dogtagpki.tps.msg.EndOp;
import org.dogtagpki.tps.msg.TPSMessage;

import com.netscape.certsrv.apps.CMS;

public class TPSSession {

    private TPSConnection connection;

    public TPSSession(TPSConnection conn) {

        if (conn == null) {
            throw new NullPointerException("TPSSession incoming connection is null!");
        }

        CMS.debug("TPSSession constructor conn: " + conn);
        connection = conn;
    }

    public TPSConnection getConnection() {
        return connection;
    }

    public TPSMessage read() throws IOException {
        TPSMessage message = null;

        CMS.debug("TPSSession.process() about to call read on connection : " + connection);

        try {
            message = connection.read();
            CMS.debug("TPSSession.process() created message " + message);

        } catch (IOException e) {
            //Catch here so we can log
            CMS.debug("TPSSession.process: Exception reading from the client: " + e.toString());
            throw e;
        }

        return message;
    }

    public void write(TPSMessage msg) throws IOException {

        try {
            connection.write(msg);
        } catch (Exception e) {
            //Catch here so we can log
            CMS.debug("Exception writing to client: " + e.toString());
            throw e;
        }

    }

    public void process() throws IOException {
        EndOp.TPSStatus status = EndOp.TPSStatus.STATUS_NO_ERROR;
        CMS.debug("In TPSSession.process()");

        TPSMessage firstMsg = read();

        TPSMessage.MsgType msg_type = firstMsg.getType();
        TPSMessage.OpType op_type = firstMsg.getOpType();

        if (msg_type != TPSMessage.MsgType.MSG_BEGIN_OP) {
            throw new IOException("Wrong first message type read in TPSSession.process!");
        }

        int result = EndOp.RESULT_GOOD;
        try {

            switch (op_type) {
            case OP_FORMAT:

                TPSProcessor processor = new TPSProcessor(this);
                BeginOp beginOp = (BeginOp) firstMsg;
                processor.process(beginOp);

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
        } catch (TPSException e) {
            //Get the status from the exception and return it to the client.
            CMS.debug("TPSSession.process: Message processing failed: " + e);
            status = e.getStatus();
            result = EndOp.RESULT_ERROR;
        } catch (IOException e) {
            CMS.debug("TPSSession.process: IO error happened during processing: " + e);
            // We get here we are done.
            throw e;

        }

        EndOp endOp = new EndOp(firstMsg.getOpType(), result, status);
        write(endOp);

        CMS.debug("TPSSession.process: leaving: result: " + result + " status: " + status);

    }

}
