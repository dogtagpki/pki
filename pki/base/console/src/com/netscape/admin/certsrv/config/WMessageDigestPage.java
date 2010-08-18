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
package com.netscape.admin.certsrv.config;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.text.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * Setup the message digest information for the installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
public class WMessageDigestPage extends WizardBasePanel implements IWizardPanel {
    protected JComboBox mRSAHashTypeBox, mDSAHashTypeBox;
    protected String mHelpIndex;
    protected String mCAKeyType;
    private static final String HELPINDEX = "install-cert-mda-wizard-help";
    
    public WMessageDigestPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));

        if (mCAKeyType.equals("RSA")) {
            mDSAHashTypeBox.setVisible(false);
            mRSAHashTypeBox.setVisible(true);
            String sha1 = mResource.getString(mPanelName+"_COMBOBOX_RSAHASHTYPE_VALUE_2");
            mRSAHashTypeBox.setSelectedItem(sha1);
        } else {
            mDSAHashTypeBox.setVisible(true);
            mRSAHashTypeBox.setVisible(false);
        }

        mHelpIndex = HELPINDEX;
        return true; 
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea hashTypeLbl = createTextArea(mResource.getString(
          mPanelName+"_TEXT_HASHTYPE_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(hashTypeLbl, gbc);

        mRSAHashTypeBox = makeJComboBox("RSAHASHTYPE");
        mRSAHashTypeBox.setVisible(true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mRSAHashTypeBox, gbc);

        mDSAHashTypeBox = makeJComboBox("DSAHASHTYPE");
        mDSAHashTypeBox.setVisible(false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mDSAHashTypeBox, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 0,COMPONENT_SPACE, COMPONENT_SPACE);
        add(dummy, gbc);

        JLabel dummy1 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(0, 0,COMPONENT_SPACE, COMPONENT_SPACE);
        add(dummy1, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
