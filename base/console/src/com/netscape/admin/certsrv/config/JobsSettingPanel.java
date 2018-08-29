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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ItemListener;

import javax.swing.JCheckBox;
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

/**
 * Jobs Scheduler setting tab
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class JobsSettingPanel extends CMSBaseTab implements ItemListener {
    private static final String HELPINDEX =
      "jobsscheduler-certsrv-setting-jobrule-help";
    private JTextField mFrequencyText;
    private JCheckBox mEnable;
    private Color mActiveColor;
    private JLabel mFrequencyLabel;
    protected AdminConnection mAdmin;
    protected CMSBaseResourceModel mModel;
    private String mServletName;
    private CMSTabPanel mParent;

    public JobsSettingPanel(String panelName, CMSTabPanel parent) {
        this(panelName, parent, true);
    }

    public JobsSettingPanel(String panelName, CMSTabPanel parent, boolean flag) {
        super(panelName, parent);
        mServletName = DestDef.DEST_JOBS_ADMIN;
        mHelpToken = HELPINDEX;
        mModel = parent.getResourceModel();
        mParent = parent;
    }

    public void init() {
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel serverInfo = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);

        //add the enable checkbox
        mEnable = makeJCheckBox("ENABLE");
        mEnable.setSelected(true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,
                                DIFFERENT_COMPONENT_SPACE,
                                0,
                                DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(mEnable, gbc);
		mCenterPanel.add(mEnable);

        //add the frequency panel
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(serverInfo, gbc);
        mCenterPanel.add(serverInfo);

        GridBagLayout gb1 = new GridBagLayout();
        serverInfo.setLayout(gb1);
		serverInfo.setBorder(makeTitledBorder("FREQUENCY"));

        // add frequency label and text field
        CMSAdminUtil.resetGBC(gbc);
        mFrequencyLabel = makeJLabel("FREQUENCY");
        mFrequencyText = makeJTextField(30);
        mActiveColor = mFrequencyText.getBackground();
        JLabel dateLabel = makeJLabel("MINUTES");
        CMSAdminUtil.addEntryField(serverInfo,
			mFrequencyLabel, mFrequencyText, dateLabel, gbc);

		refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
		nvps.put(Constants.PR_ENABLE, "");
        nvps.put(Constants.PR_JOBS_FREQUENCY, "");

        try {
            NameValuePairs val = mAdmin.read(mServletName,
              ScopeDef.SC_JOBS, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    protected void populate(NameValuePairs nvps) {
        String clientCert = "";

        String version = "";
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_JOBS_FREQUENCY)) {
                mFrequencyText.setText(value);
            } else if (name.equals(Constants.PR_ENABLE)) {
                if (value.equals(Constants.TRUE))
                    mEnable.setSelected(true);
                else
                    mEnable.setSelected(false);
            }
        }

        if (mEnable.isSelected())
            enableFields(true, mActiveColor);
        else
            enableFields(false, getBackground());
    }

    private void enableFields(boolean enable, Color color) {
        mFrequencyText.setEnabled(enable);
        mFrequencyText.setEditable(enable);
        mFrequencyText.setBackground(color);
        mFrequencyLabel.setEnabled(enable);
        mFrequencyLabel.setBackground(color);

		mFrequencyLabel.invalidate();
		mFrequencyLabel.validate();
		mFrequencyLabel.repaint(1);
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
		if (mEnable.isSelected()) {
			enableFields(true, mActiveColor);
		} else {
			enableFields(false, getBackground());
		}
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        // check blank fields
        String freq = mFrequencyText.getText().trim();

        if (freq.equals("")) {
            showMessageDialog("BLANKFIELD");
            return false;
        }

		int ifreq = 0;
		// make sure it's a positive integer
		try {
			ifreq = Integer.parseInt(freq);
		} catch (NumberFormatException e) {
			showMessageDialog("NEEDINTEGER");
			return false;
		}

		if (ifreq < 0) {
			showMessageDialog("NEEDINTEGER");
			return false;
		}

        NameValuePairs nvps = new NameValuePairs();
		if (mEnable.isSelected())
			nvps.put(Constants.PR_ENABLE, Constants.TRUE);
		else
			nvps.put(Constants.PR_ENABLE, Constants.FALSE);

        if (mEnable.isSelected()){
            nvps.put(Constants.PR_JOBS_FREQUENCY, freq);
		}

        mModel.progressStart();
        try {
            mAdmin.modify(mServletName, ScopeDef.SC_JOBS,
              Constants.RS_ID_CONFIG, nvps);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
            return false;
        }

        mModel.progressStop();
        clearDirtyFlag();
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

