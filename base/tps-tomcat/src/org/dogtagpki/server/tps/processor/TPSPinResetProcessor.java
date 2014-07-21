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
package org.dogtagpki.server.tps.processor;

import java.io.IOException;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;

public class TPSPinResetProcessor extends TPSProcessor {

    public TPSPinResetProcessor(TPSSession session) {
        super(session);
        // TODO Auto-generated constructor stub
    }

    @Override
    public void process(BeginOpMsg beginMsg) throws TPSException, IOException {
        if (beginMsg == null) {
            throw new TPSException("TPSPinResetProcessor.process: invalid input data, not beginMsg provided.",
                    TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }
        setBeginMessage(beginMsg);
        setCurrentTokenOperation("pinReset");

        resetPin();

    }

    private void resetPin() throws TPSException {

        //ToDo: Implement full pin reset processor, the pin reset portion
        // of an enrollment works fine. We just need to finish this to perform
        // a completely stand alone pin reset of an already enrolled token.
        CMS.debug("TPSPinResetProcessor.resetPin: entering...");

        throw new TPSException("TPSPinResetProcessor.resetPin: Pin Reset standalone operation not yet supported!",
                TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);

    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
