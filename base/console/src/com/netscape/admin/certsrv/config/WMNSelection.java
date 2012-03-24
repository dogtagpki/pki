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
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * MNSelection page for reconfiguring the Recovery MN Scheme
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
class WMNSelection extends WizardBasePanel
    implements IWizardPanel
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANELNAME = "WMNSELECTION";

    private JTextField mMField, mNField;
    private JLabel mMLabel, mNLabel;
    private int mRequired, mAvail;

    private MNSchemeWizardInfo mInfo;
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

	/*==========================================================
     * constructors
     *==========================================================*/
    WMNSelection() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    public boolean initializePanel(WizardInfo info) {
        //let's set the values
        mInfo = (MNSchemeWizardInfo)info;
        mMField.setText(mInfo.getNewM());
        mNField.setText(mInfo.getNewN());
        mMLabel.setText(mInfo.getM());
        mNLabel.setText(mInfo.getN());
        return true;
    }

    public boolean validatePanel() {
        if ((mMField.getText().trim().equals("")) ||
            (mNField.getText().trim().equals("")) ) {
            setErrorMessage("CANNOTBEBLANK");
            return false;    
        }

        String str = mMField.getText().trim();
        if (str.equals("")) {
            setErrorMessage("CANNOTBEBLANK");
            return false;
        }

        try {
            mRequired = Integer.parseInt(str);
            str = mNField.getText().trim();
            if (str.equals("")) {
                setErrorMessage("CANNOTBEBLANK");
                return false;
            }
            mAvail = Integer.parseInt(str);
        } catch (NumberFormatException e) {
            setErrorMessage("NOTINTEGER");
            return false;
        }

        if (mRequired <= 0 || mAvail <= 0) {
            setErrorMessage("NONZERO");
            return false;
        }

        if (mRequired > mAvail) {
            setErrorMessage("LARGER");
            return false;
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
        mInfo.add(Constants.PR_RECOVERY_M, mMField.getText().trim());
        mInfo.add(Constants.PR_RECOVERY_N, mNField.getText().trim());
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    //base class take care of these
    //public String getTitle();
    //public String getErrorMessage();

    /*==========================================================
	 * private methods
     *==========================================================*/

    //initialize the panel
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        //show icon
        JLabel iconLabel = new JLabel(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_CERTICON_LARGE));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(iconLabel,gbc);
        add(iconLabel);

        //show wizard description
        JTextArea desc = new JTextArea(
            CMSAdminUtil.wrapText(
            mResource.getString("WMNSELECTION_TEXT_DESC_LABEL"),60),2,60);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.1;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                   COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        //current setting
        JPanel oldPanel = new JPanel();
        oldPanel.setBorder(makeTitledBorder("OLDSCHEME"));
        GridBagLayout gb1 = new GridBagLayout();
        oldPanel.setLayout(gb1);

        //m
        JLabel label1 = makeJLabel("M");
        mMLabel = new JLabel("");
        CMSAdminUtil.resetGBC(gbc);
        CMSAdminUtil.addEntryField(oldPanel, label1, mMLabel, gbc);

        //n
        JLabel label3 = makeJLabel("N");
        mNLabel = new JLabel("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridheight = gbc.REMAINDER;
        CMSAdminUtil.addEntryField(oldPanel, label3, mNLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                   COMPONENT_SPACE,COMPONENT_SPACE);
      	gb.setConstraints(oldPanel,gbc);
        add(oldPanel);

        //new setting
        JPanel newPanel = new JPanel();
        newPanel.setBorder(makeTitledBorder("NEWSCHEME"));
        GridBagLayout gb2 = new GridBagLayout();
        newPanel.setLayout(gb2);

        //m
        JLabel label5 = makeJLabel("M");
        mMField = new JTextField("");
        CMSAdminUtil.resetGBC(gbc);
        CMSAdminUtil.addEntryField(newPanel, label5, mMField, gbc);

        //n
        JLabel label6 = makeJLabel("N");
        mNField = new JTextField("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridheight = gbc.REMAINDER;
        CMSAdminUtil.addEntryField(newPanel, label6, mNField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.9;
        gb.setConstraints(newPanel,gbc);
        add(newPanel);

        super.init();
    }

}
