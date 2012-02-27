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

import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.math.*;

/**
 * OCSP General Setting
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSOCSPGeneralPanel extends CMSBaseTab implements ItemListener {

    private static String PANEL_NAME = "OCSPGENERAL";
    private static CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    private JCheckBox mRAEnable;
    private JCheckBox mEEEnable;
    private CMSTabPanel mParent;
    private JComboBox mGroups;
    private JComboBox mAlgorithms;
    private JTextField mSerialNumber;
    private JTextField mMaxSerialNumber;
    private JCheckBox mValidity;
    private Vector mGroupData;
    private static final String OCSPHELPINDEX =
      "configuration-ocsp-general-help";

    public CMSOCSPGeneralPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = OCSPHELPINDEX;
    }

    public void init() {
        Debug.println("CMSCAGeneral: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);

        JPanel signingPanel = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        signingPanel.setLayout(gb2);
        signingPanel.setBorder(makeTitledBorder("SIGNING"));

        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
//        gb.setConstraints(adminPanel, gbc);
//        mCenterPanel.add(adminPanel);
        

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(signingPanel, gbc);
        mCenterPanel.add(signingPanel);
        

        CMSAdminUtil.resetGBC(gbc);
        JLabel signingLabel = makeJLabel("ALGORITHM");
        gbc.anchor = gbc.CENTER;
        gb2.setConstraints(signingLabel, gbc);
        gbc.weighty = 1.0;
        signingPanel.add(signingLabel);

        CMSAdminUtil.resetGBC(gbc);
        mAlgorithms = new JComboBox();
        mAlgorithms.addItemListener(this);
        //mAlgorithms = makeJComboBox("ALGORITHM");
        gbc.anchor = gbc.NORTHWEST;
        //gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        //gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb2.setConstraints(mAlgorithms, gbc);
        signingPanel.add(mAlgorithms);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy1 = new JLabel(" ");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb2.setConstraints(dummy1, gbc);
        signingPanel.add(dummy1);

        refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_DEFAULT_ALGORITHM, "");
        nvps.put(Constants.PR_ALL_ALGORITHMS, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_OCSP_ADMIN,
              ScopeDef.SC_GENERAL, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
    }

    protected void populate(NameValuePairs nvps) {
        String defaultAlgorithm = "";
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_DEFAULT_ALGORITHM)) {
                defaultAlgorithm = value;
            } else if (name.equals(Constants.PR_ALL_ALGORITHMS)) {
                initAlgorithmBox(value);
            }
        }

        mAlgorithms.setSelectedItem(defaultAlgorithm);
    }

    private void initAlgorithmBox(String val) {
        if (mAlgorithms.getItemCount() >= 0) {
            mAlgorithms.removeAllItems();
        }
        StringTokenizer tokenizer = new StringTokenizer(val, ":");
        while (tokenizer.hasMoreTokens()) {
            mAlgorithms.addItem(tokenizer.nextToken());
        }
    }

    private boolean getBoolean(String str) {
        if (str.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
    }

    private String hexToDecimal(String hex)
    {
        //String newHex = hex.substring(2);
        BigInteger bi = new BigInteger(hex, 16);
        return bi.toString();
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        NameValuePairs nvps = new NameValuePairs();

        nvps.put(Constants.PR_DEFAULT_ALGORITHM,
                (String) mAlgorithms.getSelectedItem());

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_OCSP_ADMIN,
              ScopeDef.SC_GENERAL, Constants.RS_ID_CONFIG, nvps);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
            return false;
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    public boolean resetCallback() {
        refresh();
        return true;
    }
}
