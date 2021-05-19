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

import javax.swing.JCheckBox;
import javax.swing.JPanel;

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
 * RA General Setting
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSRAGeneralPanel extends CMSBaseTab {

    private static String PANEL_NAME = "RAGENERAL";
    private static CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    private JCheckBox mEEEnable;
    private CMSTabPanel mParent;
    private static final String HELPINDEX =
      "configuration-ra-general-help";

    public CMSRAGeneralPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    @Override
    public void init() {
        Debug.println("CMSRAGeneral: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);

        JPanel adminPanel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        adminPanel.setLayout(gb1);
        adminPanel.setBorder(makeTitledBorder("PARAMETERS"));

        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(adminPanel, gbc);
        mCenterPanel.add(adminPanel);

        CMSAdminUtil.resetGBC(gbc);
        mEEEnable = makeJCheckBox("EE");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb1.setConstraints(mEEEnable, gbc);
        adminPanel.add(mEEEnable);

/*
        CMSAdminUtil.resetGBC(gbc);
        mRAEnable = makeJCheckBox("RA");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb1.setConstraints(mRAEnable, gbc);
        adminPanel.add(mRAEnable);
*/

        refresh();
    }

    @Override
    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_EE_ENABLED, "");
        //nvps.add(Constants.PR_RA_ENABLED, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_RA_ADMIN,
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
        Debug.println("RA General Received: "+nvps.toString());
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_EE_ENABLED)) {
                mEEEnable.setSelected(getBoolean(value));
/*
            } else if (name.equals(Constants.PR_RA_ENABLED)) {
                mRAEnable.setSelected(getBoolean(value));
*/
            }
        }
    }

    private boolean getBoolean(String str) {
        if (str.equals(Constants.TRUE))
            return true;
        return false;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    @Override
    public boolean applyCallback() {
        NameValuePairs nvps = new NameValuePairs();

        if (mEEEnable.isSelected())
            nvps.put(Constants.PR_EE_ENABLED, Constants.TRUE);
        else
            nvps.put(Constants.PR_EE_ENABLED, Constants.FALSE);

/*
        if (mRAEnable.isSelected())
            nvps.add(Constants.PR_RA_ENABLED, Constants.TRUE);
        else
            nvps.add(Constants.PR_RA_ENABLED, Constants.FALSE);
*/

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_RA_ADMIN,
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
    @Override
    public boolean resetCallback() {
        refresh();
        return true;
    }
}
