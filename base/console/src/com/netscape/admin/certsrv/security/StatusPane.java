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
import javax.swing.border.*;

import java.util.*;
import java.awt.*;

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class StatusPane extends JPanel implements IKeyCertPage, SuiConstants {

    boolean show = false;
    boolean error = false;

    MultilineLabel statusText = new MultilineLabel();

    public JPanel getPanel() {
        show = false;
        return this;
    }

    public boolean pageShow(WizardObservable observable) {
        return show;
    }

    public boolean pageHide(WizardObservable observable) {
        show = false;
        error = false;
        return true;
    }

    public void setShow(boolean show) {
        this.show = show;
    }


    public boolean hasError() {
        return error;
    }

    public void setMessage(Vector messages) {
        String status = "";
        int nMessage = messages.size();
        for (int i = 0; i < nMessage; i++) {
            if (getMessage((Message)(messages.elementAt(i))).length() !=
                    0) {
                status += getMessage((Message)(messages.elementAt(i))) +
                        "\n\n";
            }
        }

        //((LABELeditor)(statusPane.getCtrlByName("statusText"))).setValueS(status);
        statusText.setText(status);

    }

    public void setMessage(String message) {
        statusText.setText(message);
    }

    public void appendMessage(String message) {
        StringBuffer sb = new StringBuffer(statusText.getText().trim());
        sb.append(message);
        statusText.setText(sb.toString());
    }


    String getMessage(Message message) {
        String status = "";

        if (message.getStatus() == message.NMC_SUCCESS) {
            status = message.getDescription() + message.getExtraMessage();
        } else if (message.getStatus() == message.NMC_FAILURE) {
            status += message.getErrorType() + "\n";
            status += message.getErrorInfo() + "\n";
            status += message.getErrorDetail();
            error = true;
        } else if (message.getStatus() == message.NMC_WARNING) {
            status += message.getDescription();
        } else if (message.getStatus() == message.NMC_UNKNOWN) {
            status += message.getDescription();
            error = true;
        }

        return status;
    }

    public void setMessage(Message message) {
        //((LABELeditor)(statusPane.getCtrlByName("statusText"))).setValueS(getMessage(message));
        statusText.setText(getMessage(message));
    }

    public void setLastPage(boolean isLastpage) {
        if (isLastpage) {
            next.setText("");
        } else {
            next.setText(resource.getString(null, "clickNextToContinue"));
        }
    }


    ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();
    JLabel next = new JLabel();

    public StatusPane() {
        //set up layout here;
        super();

        //setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setLayout(new GridBagLayout());

        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("StatusPane", "title")));

        GridBagUtil.constrain(this, statusText, 0, 0, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(), 0, 1, 1,
                1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        next.setText(resource.getString(null, "clickNextToContinue"));

        GridBagUtil.constrain(this, next, 0, 2, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);


        //add(statusText);
    }
}
