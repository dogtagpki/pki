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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ItemListener;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;

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
    private JComboBox<String> mAlgorithms;
    private JTextField mSerialNumber;
    private JTextField mMaxSerialNumber;
    private JCheckBox mValidity;
    private Vector<Object> mGroupData;
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
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
//        gb.setConstraints(adminPanel, gbc);
//        mCenterPanel.add(adminPanel);


        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(signingPanel, gbc);
        mCenterPanel.add(signingPanel);


        CMSAdminUtil.resetGBC(gbc);
        JLabel signingLabel = makeJLabel("ALGORITHM");
        gbc.anchor = GridBagConstraints.CENTER;
        gb2.setConstraints(signingLabel, gbc);
        gbc.weighty = 1.0;
        signingPanel.add(signingLabel);

        CMSAdminUtil.resetGBC(gbc);
        mAlgorithms = new JComboBox<>();
        mAlgorithms.addItemListener(this);
        //mAlgorithms = makeJComboBox("ALGORITHM");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        //gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb2.setConstraints(mAlgorithms, gbc);
        signingPanel.add(mAlgorithms);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy1 = new JLabel(" ");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
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

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
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
