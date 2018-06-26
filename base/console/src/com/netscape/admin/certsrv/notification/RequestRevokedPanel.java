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
package com.netscape.admin.certsrv.notification;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ItemListener;

import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.config.CMSBaseTab;
import com.netscape.admin.certsrv.config.CMSTabPanel;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;

/**
 * notification settings tab for RequestCompletion
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class RequestRevokedPanel extends CMSBaseTab implements ItemListener {
    private static final String RA_HELPINDEX =
      "configuration-notifications";
    private static final String CA_HELPINDEX =
      "configuration-notifications";
    private JTextField mEmailFormText;
    private JTextField mEmailSubjectText;
    private JCheckBox mEnable;
    private Color mActiveColor;
    private JLabel mEmailFormLabel;
    private JLabel mEmailSubjectLabel;
    private JTextField mSenderEmailText;
    private JLabel mSenderEmailLabel;
    protected AdminConnection mAdmin;
    protected CMSBaseResourceModel mModel;
    private String mServletName;
    private CMSTabPanel mParent;
    private String mPanelName;

	/*
    public RequestRevokedPanel(String panelName, CMSTabPanel parent) {
        this(panelName, parent, true);
        mPanelName = panelName;
    }
    */
    public RequestRevokedPanel(String panelName, CMSTabPanel parent,
								String servletName) {
        super(panelName, parent);
        if (servletName.equals(DestDef.DEST_RA_ADMIN)) {
          mHelpToken = RA_HELPINDEX;
        } else {
          mHelpToken = CA_HELPINDEX;
        }
        mServletName = servletName;
        mModel = parent.getResourceModel();
        mParent = parent;
    }

    public void init() {
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel emailInfo = new JPanel();
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

        //add the setting panel
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(emailInfo, gbc);
        mCenterPanel.add(emailInfo);

        GridBagLayout gb1 = new GridBagLayout();
        emailInfo.setLayout(gb1);
		emailInfo.setBorder(makeTitledBorder("EMAILINFO"));

        // add sender email label and text field
        CMSAdminUtil.resetGBC(gbc);
        mSenderEmailLabel = makeJLabel("SENDER");
        mSenderEmailText = makeJTextField(30);
		mActiveColor = mSenderEmailText.getBackground();
        CMSAdminUtil.addEntryField(emailInfo,
			mSenderEmailLabel, mSenderEmailText, gbc);

        // add email subject label and text field
        CMSAdminUtil.resetGBC(gbc);
        mEmailSubjectLabel = makeJLabel("SUBJECT");
        mEmailSubjectText = makeJTextField(30);
		mActiveColor = mEmailSubjectText.getBackground();
        CMSAdminUtil.addEntryField(emailInfo,
			mEmailSubjectLabel, mEmailSubjectText, gbc);

        // add form name label and text field
        CMSAdminUtil.resetGBC(gbc);
        mEmailFormLabel = makeJLabel("FORMNAME");
        mEmailFormText = makeJTextField(30);
		mActiveColor = mEmailFormText.getBackground();
        CMSAdminUtil.addEntryField(emailInfo,
			mEmailFormLabel, mEmailFormText, gbc);

		refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
		nvps.put(Constants.PR_ENABLE, "");
        nvps.put(Constants.PR_NOTIFICATION_FORM_NAME, "");
        nvps.put(Constants.PR_NOTIFICATION_SUBJECT, "");
        nvps.put(Constants.PR_NOTIFICATION_SENDER, "");

        try {
            NameValuePairs val = mAdmin.read(mServletName,
              ScopeDef.SC_NOTIFICATION_REV_COMP, Constants.RS_ID_CONFIG, nvps);

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
            if (name.equals(Constants.PR_NOTIFICATION_FORM_NAME)) {
                mEmailFormText.setText(value);
            } else if (name.equals(Constants.PR_NOTIFICATION_SUBJECT)) {
                mEmailSubjectText.setText(value);
            } else if (name.equals(Constants.PR_NOTIFICATION_SENDER)) {
                mSenderEmailText.setText(value);
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
        mEmailFormText.setEnabled(enable);
        mEmailFormText.setEditable(enable);
        mEmailFormText.setBackground(color);
        mEmailFormLabel.setEnabled(enable);
        mEmailFormLabel.setBackground(color);

        mEmailSubjectText.setEnabled(enable);
        mEmailSubjectText.setEditable(enable);
        mEmailSubjectText.setBackground(color);
        mEmailSubjectLabel.setEnabled(enable);
        mEmailSubjectLabel.setBackground(color);

        mSenderEmailText.setEnabled(enable);
        mSenderEmailText.setEditable(enable);
        mSenderEmailText.setBackground(color);
        mSenderEmailLabel.setEnabled(enable);
        mSenderEmailLabel.setBackground(color);

		repaintComp(mEmailFormLabel);
		repaintComp(mSenderEmailLabel);
		repaintComp(mEmailSubjectLabel);
    }

    private void repaintComp(JComponent component) {
        component.invalidate();
        component.validate();
        component.repaint(1);
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
        String emailForm = mEmailFormText.getText().trim();
		String emailSubject = mEmailSubjectText.getText().trim();
        String senderEmail = mSenderEmailText.getText().trim();

        if (mEnable.isSelected() && (emailForm.equals("") ||
			                         senderEmail.equals("") ||
                                     emailSubject.equals(""))) {
            showMessageDialog("BLANKFIELD");
            return false;
        }

        NameValuePairs nvps = new NameValuePairs();
		if (mEnable.isSelected())
			nvps.put(Constants.PR_ENABLE, Constants.TRUE);
		else
			nvps.put(Constants.PR_ENABLE, Constants.FALSE);

        if (mEnable.isSelected()){
            nvps.put(Constants.PR_NOTIFICATION_FORM_NAME, emailForm);
            nvps.put(Constants.PR_NOTIFICATION_SUBJECT, emailSubject);
            nvps.put(Constants.PR_NOTIFICATION_SENDER, senderEmail);
		}

        mModel.progressStart();
        try {
            mAdmin.modify(mServletName, ScopeDef.SC_NOTIFICATION_REV_COMP,
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

