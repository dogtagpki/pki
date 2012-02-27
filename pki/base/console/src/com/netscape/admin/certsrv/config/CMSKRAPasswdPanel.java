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
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.ug.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.awt.event.*;

/**
 * KRA password management tab
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSKRAPasswdPanel extends CMSBaseUGTab {
    private static String PANEL_NAME = "KRAPASSWD";
    private CMSBaseResourceModel mModel;
    private JButton mPwdBtn;
    private AdminConnection mAdmin;
    private JList mAgentList;
    private DefaultListModel mAgentModel;
    private Icon mUserIcon;
    private JButton mRefresh, mHelp;
    private static final String HELPINDEX =
      "configuration-kra-agentpwd-help";
    private CMSUGTabPanel mParent = null;

    public CMSKRAPasswdPanel(CMSUGTabPanel parent) {
        super(PANEL_NAME, parent.getResourceModel());
        mModel = parent.getResourceModel();
        mAdmin = mModel.getServerInfo().getAdmin();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_RECOVERY_AGENT, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_KRA_ADMIN,
              ScopeDef.SC_RECOVERY, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            mParent.removeAll();
            //showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
    }

    protected void populate(NameValuePairs nvps) {
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_RECOVERY_AGENT)) {
                mAgentModel.removeAllElements();
                updateModel(value);
            }
        }
    }

    private void updateModel(String value) {
        String[] uids = getUIDs(value);
        for (int i=0; i<uids.length; i++) {
            JLabel label = makeJLabel(mUserIcon, uids[i],
              SwingConstants.LEFT);
            mAgentModel.add(i, label);
        }

        if (mAgentModel.size() > 0)
            mAgentList.setSelectedIndex(0);
        setSelectedItem();
    }

    private String[] getUIDs(String uids) {
        StringTokenizer tokenizer = new StringTokenizer(uids, ",");
        String[] vals = new String[tokenizer.countTokens()];
        int i=0;
        while (tokenizer.hasMoreElements()) {
            vals[i++] = (String)tokenizer.nextElement();
        }
        CMSAdminUtil.bubbleSort(vals);
        return vals;
    }

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        //JButton[] buttons = { mRefresh, mHelp };
        JButton[] buttons = { mRefresh };
        return makeJButtonPanel(buttons, true);
    }

    protected JPanel createListPanel() {
        JPanel mainPanel = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mainPanel.setLayout(gb3);

        JPanel listPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        listPanel.setLayout(gb);
        listPanel.setBorder(makeTitledBorder("RECOVERYLIST"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        gb3.setConstraints(listPanel, gbc);
        mainPanel.add(listPanel);

        // label for table
        JLabel tablelbl = makeJLabel("RECOVERYLIST");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 0;
        //gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gb.setConstraints(tablelbl, gbc);
        listPanel.add(tablelbl);

        // agent table
        mAgentModel = new DefaultListModel();
        mAgentList = makeJList(mAgentModel, 10);
        mAgentList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        MouseListener mouseListener = new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2)
                    displayPasswordDialog();
                else
                    setSelectedItem();
            }
        };

        mAgentList.addMouseListener(mouseListener);
        mUserIcon = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USER);
        JScrollPane scrollPane = createScrollPane(mAgentList);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridheight = gbc.REMAINDER;
        gb.setConstraints(scrollPane, gbc);
        listPanel.add(scrollPane);

        // change password button
        mPwdBtn = makeJButton("CHANGEPWD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(mPwdBtn, gbc);
        listPanel.add(mPwdBtn);

        refresh();

        return mainPanel;
    }

    private JScrollPane createScrollPane(JList listbox) {

        JScrollPane scrollPane = new JScrollPane(listbox,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setBackground(getBackground());
        scrollPane.setAlignmentX(LEFT_ALIGNMENT);
        scrollPane.setAlignmentY(TOP_ALIGNMENT);
        scrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        return scrollPane;
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            refresh();
        } else if (e.getSource().equals(mHelp)) {
            helpCallback();
        } else if (e.getSource().equals(mPwdBtn)) {
            displayPasswordDialog();
        }
    }

    public void displayPasswordDialog() {
        Object[] values = mAgentList.getSelectedValues();
        if (values.length == 0) {
            showMessageDialog("NOSELECTION");
        } else if (values.length > 1) {
            showMessageDialog("MULTISELECTIONS");
        } else {
            String str = ((JLabel)values[0]).getText();

			// ensure the selected id is valid
			refresh();
			int s = mAgentList.getModel().getSize();
			boolean foundID = false;
			for (int i = 0; i < s; i++) {
				JLabel l = (JLabel)mAgentList.getModel().getElementAt(i);
				if (str.equals(l.getText())) {
					foundID = true;
					break;
				}
			}
			if (foundID) {
            	JDialog pwdDialog = new CMSPasswordDialog(mModel.getFrame(),
              		mAdmin, str);
			} else {
            	showErrorDialog("Invalid ID");
			}
        }
    }

    private void setSelectedItem() {
        if (mAgentList.getSelectedIndex()< 0) {
            mPwdBtn.setEnabled(false);
            return;
        }

        if (mAgentList.getSelectedIndex() >= 0)
            mPwdBtn.setEnabled(true);
    }

    public void mouseClicked(MouseEvent e) {
/*
                if (e.getClickCount() == 2)
                    displayPasswordDialog();
                else
                    setSelectedItem();
*/
    }
}

