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
package com.netscape.admin.certsrv.security;

import javax.swing.*;

import java.awt.SystemColor;
import java.util.*;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.nmclf.*;

class MessageDialog {

    public static void rpt_success(Message message) {
        SuiOptionPane.showMessageDialog(
                UtilConsoleGlobals.getActivatedFrame(),
                message.getDescription());
    }

    public static void rpt_error(Message message) {
        Object m[] = new Object[6];
        m[0] = message.getErrorType();
        m[2] = " ";
        m[1] = message.getErrorInfo();
        m[3] = message.getErrorDetail();
        if (message.getExtraMessage().length() != 0) {
            m[4] = " ";
            m[5] = message.getExtraMessage();
        }
        SuiOptionPane.showMessageDialog((new JFrame()), m);
    }

    public static void messageDialog(Message cgiMessage) {
        switch (cgiMessage.getStatus()) {
        case Message.NMC_SUCCESS:
            rpt_success(cgiMessage);
            break;
        case Message.NMC_FAILURE:
            rpt_error(cgiMessage);
            break;
        case Message.NMC_WARNING:
            rpt_error(cgiMessage);
            break;
        case Message.NMC_UNKNOWN:
            rpt_success(cgiMessage);
            break;
        default :
            break;
        }
    }
}
