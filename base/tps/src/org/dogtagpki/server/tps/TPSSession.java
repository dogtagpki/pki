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

import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.main.ExternalRegAttrs;
import org.dogtagpki.server.tps.processor.TPSEnrollProcessor;
import org.dogtagpki.server.tps.processor.TPSPinResetProcessor;
import org.dogtagpki.server.tps.processor.TPSProcessor;
import org.dogtagpki.tps.TPSConnection;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg;
import org.dogtagpki.tps.msg.TPSMessage;

public class TPSSession {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSSession.class);

    private TPSConnection connection;
    private String ipAddress; /* remote IP */
    private TokenRecord tokenRecord;

    private ExternalRegAttrs extRegAttrs;

    public TPSSession(TPSConnection conn, String ip) {

        if (conn == null) {
            throw new NullPointerException("TPSSession incoming connection is null!");
        }

        logger.debug("TPSSession constructor conn: " + conn);
        connection = conn;

        if (ip == null) {
         // probably unlikely to happen; log it and continue anyway
            logger.debug("TPSSession constructor remote ipAddress null");
        } else {
            logger.debug("TPSSession constructor remote ipAddress: " + getIpAddress());
        }
        setIpAddress(ip);

    }

    public TPSConnection getConnection() {
        return connection;
    }

    public TPSMessage read() throws IOException {
        TPSMessage message = null;

        logger.debug("TPSSession.read() about to call read on connection : " + connection);

        try {
            message = connection.read();
            //logger.debug("TPSSession.read() created message " + message);
            logger.debug("TPSSession.read() message created");

        } catch (IOException e) {
            //Catch here so we can log
            logger.error("TPSSession.process: Exception reading from the client: " + e.getMessage(), e);
            throw e;
        }

        return message;
    }

    public void write(TPSMessage msg) throws IOException {

        try {
            connection.write(msg);
        } catch (Exception e) {
            logger.error("Exception writing to client: " + e.getMessage(), e);
            throw e;
        }

    }

    public void process() throws IOException {
        EndOpMsg.TPSStatus status = EndOpMsg.TPSStatus.STATUS_NO_ERROR;
        logger.debug("In TPSSession.process()");

        TPSMessage firstMsg = read();

        TPSMessage.MsgType msg_type = firstMsg.getType();
        TPSMessage.OpType op_type = firstMsg.getOpType();

        if (msg_type != TPSMessage.MsgType.MSG_BEGIN_OP) {
            throw new IOException("Wrong first message type read in TPSSession.process!");
        }

        int result = EndOpMsg.RESULT_ERROR;
        BeginOpMsg beginOp = (BeginOpMsg) firstMsg;
        try {
            switch (op_type) {
            case OP_FORMAT:

                //Assume success, processor will indicate otherwise
                result = EndOpMsg.RESULT_GOOD;
                TPSProcessor processor = new TPSProcessor(this);
                processor.process(beginOp);
                break;

            case OP_ENROLL:
                //Assume success, processor will indicate otherwise
                result = EndOpMsg.RESULT_GOOD;
                TPSEnrollProcessor enrollProcessor = new TPSEnrollProcessor(this);
                enrollProcessor.process(beginOp);
                break;
            case OP_RENEW:
                break;
            case OP_RESET_PIN:
                result = EndOpMsg.RESULT_GOOD;
                TPSPinResetProcessor pinResetProcessor = new TPSPinResetProcessor(this);
                pinResetProcessor.process(beginOp);
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
            logger.warn("TPSSession.process: Message processing failed: " + e.getMessage(), e);
            status = e.getStatus();
            result = EndOpMsg.RESULT_ERROR;
        } catch (IOException e) {
            logger.error("TPSSession.process: IO error happened during processing: " + e.getMessage(), e);
            // We get here we are done.
            throw e;

        }

        EndOpMsg endOp = new EndOpMsg(firstMsg.getOpType(), result, status);
        write(endOp);

        logger.debug("TPSSession.process: leaving: result: " + result + " status: " + status);

    }

    public TokenRecord getTokenRecord() {
        return tokenRecord;
    }

    public void setTokenRecord(TokenRecord tokenRecord) {
        this.tokenRecord = tokenRecord;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    private void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setExternalRegAttrs(ExternalRegAttrs erAttrs) {
        extRegAttrs = erAttrs;
    }

    public ExternalRegAttrs getExternalRegAttrs() {
        return extRegAttrs;
    }
}
