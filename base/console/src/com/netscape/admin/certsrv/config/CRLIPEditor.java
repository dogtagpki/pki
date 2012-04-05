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
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * CRL IP Editor
 *
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CRLIPEditor extends JDialog implements ActionListener {

    private final static String PREFIX = "CRLIPEDITOR";
    private final static String HELPINDEX =
        "configuration-revocation";
    private JButton mOK, mCancel, mHelp;
    private String mName;
    private JTextField mNameText, mDescText;
    private ResourceBundle mResource;
    private JFrame mParentFrame;
    private AdminConnection mAdmin;
    private JLabel nameLabel, descLabel;
    private Color mActiveColor;
    private String mDest;
    private JCheckBox mEnableBox;
    private boolean mEnable = true;
    private String mInstanceName;
    private Vector mNames;

    public CRLIPEditor(AdminConnection admin, JFrame parent,
        String name, String dest, String instanceName, Vector names) {
        super(parent,true);
        mParentFrame = parent;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mAdmin = admin;
        mName = name;
        mNames = names;
        mInstanceName = instanceName;
        mDest = dest;
        setSize(600, 180);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        //gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(content, gbc);
        center.add(content);

        //action panel
        JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(action, gbc);
        center.add(action);

        getContentPane().add("Center",center);
    }

    public void showDialog(NameValuePairs values) {

        for (String name : values.keySet()) {
            String val = values.get(name);
            if ((mName == null || mName.length() == 0) &&
                name.equals(Constants.PR_ID)) {
                mNameText.setText(val);
            } else if (name.equals(Constants.PR_DESCRIPTION)) {
                mDescText.setText(val);
            } else if (name.equals(Constants.PR_ENABLED)) {
                if (val.equalsIgnoreCase(Constants.TRUE))
                    mEnable = true;
                else
                    mEnable = false;
            }
        }

        mEnableBox.setSelected(mEnable);
        enableCRLIP();
        this.show();
    }

    public String getCRLName() {
        return mNameText.getText().trim();
    }

    private void enableCRLIP() {
        if (mName == null || mName.length() == 0) {
            nameLabel.setEnabled(true);
            mNameText.setBackground(mActiveColor);
            mNameText.setEnabled(true);
            mNameText.setEditable(true);

            descLabel.setEnabled(true);
            mDescText.setBackground(mActiveColor);
            mDescText.setEnabled(true);
            mDescText.setEditable(true);

            CMSAdminUtil.repaintComp(nameLabel);
            CMSAdminUtil.repaintComp(mNameText);
        } else if (mEnable) {
            descLabel.setEnabled(true);
            mDescText.setBackground(mActiveColor);
            mDescText.setEnabled(true);
            mDescText.setEditable(true);
        } else {
            descLabel.setEnabled(false);
            mDescText.setBackground(getBackground());
            mDescText.setEnabled(false);
            mDescText.setEditable(false);
        }

        CMSAdminUtil.repaintComp(descLabel);
        CMSAdminUtil.repaintComp(mDescText);
    }

    private JPanel makeContentPanel() {
        JPanel mainPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mainPanel.setLayout(gb);

        if (mName != null && mName.length() > 0) {
            CMSAdminUtil.resetGBC(gbc);
            JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX,
                                                    "CRLIPNAME", null);
            gbc.anchor = gbc.WEST;
            //gbc.weightx = 1.0;
            gbc.fill = gbc.NONE;
            gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE);
            gb.setConstraints(label1, gbc);
            mainPanel.add(label1);

            CMSAdminUtil.resetGBC(gbc);
            JLabel label2 = new JLabel(mName);
            gbc.anchor = gbc.WEST;
            gbc.gridwidth = gbc.REMAINDER;
            gbc.weightx = 0.0;
            gbc.fill = gbc.NONE;
            gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE);
            gb.setConstraints(label2, gbc);
            mainPanel.add(label2);
        }

        CMSAdminUtil.resetGBC(gbc);
        mEnableBox = CMSAdminUtil.makeJCheckBox(mResource, PREFIX,
          "ENABLE", null, false, this);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(mEnableBox, gbc);
        mainPanel.add(mEnableBox);

        if (mName == null || mName.length() == 0) {
            CMSAdminUtil.resetGBC(gbc);
            nameLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
              "CRLIPNAME", null);
            gbc.anchor = gbc.EAST;
            gbc.fill = gbc.NONE;
            gbc.weightx = 0.0;
            gbc.insets = new Insets(0, 0,
                                    CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE);
            gb.setConstraints(nameLabel, gbc);
            mainPanel.add(nameLabel);

            CMSAdminUtil.resetGBC(gbc);
            mNameText = new JTextField(30);
            gbc.anchor = gbc.WEST;
            gbc.weightx = 0.0;
            gbc.fill = gbc.NONE;
            gbc.gridwidth = gbc.REMAINDER;
            //gbc.gridheight = gbc.REMAINDER;
            gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE,
                                    CMSAdminUtil.COMPONENT_SPACE);
            gb.setConstraints(mNameText, gbc);
            mainPanel.add(mNameText);
            //mActiveColor = mNameText.getBackground();
        }

        CMSAdminUtil.resetGBC(gbc);
        descLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "DESCRIPTION", null);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0,
                                CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gb.setConstraints(descLabel, gbc);
        mainPanel.add(descLabel);

        CMSAdminUtil.resetGBC(gbc);
        mDescText = new JTextField(30);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gb.setConstraints(mDescText, gbc);
        mainPanel.add(mDescText);
        mActiveColor = mDescText.getBackground();

        return mainPanel;
    }

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
        //JButton[] buttons = { mOK, mCancel, mHelp};
        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    public void actionPerformed(ActionEvent e) {

        if (e.getSource().equals(mEnableBox)) {
            mEnable = mEnableBox.isSelected();
            enableCRLIP();
        } else if (e.getSource().equals(mCancel)) {
            this.dispose();
        } else if (e.getSource().equals(mOK)) {
            NameValuePairs nvps = new NameValuePairs();

            if (mName != null && mName.length() > 0) {
                nvps.put(Constants.PR_ID, mName);
            } else {
                nvps.put(Constants.PR_ID, mNameText.getText().trim());
            }

            nvps.put(Constants.PR_DESCRIPTION, mDescText.getText().trim());

            if (mEnable) {
                nvps.put(Constants.PR_ENABLED, Constants.TRUE);
            } else {
                nvps.put(Constants.PR_ENABLED, Constants.FALSE);
            }

            try {
                if (mName != null && mName.length() > 0) {
                    mAdmin.modify(mDest, ScopeDef.SC_CRLIPS, Constants.OP_SET, nvps);
                } else {
                    for (int i = 0; i < mNames.size(); i++) {
                        String name = (String)mNames.elementAt(i);
                        if (name.equalsIgnoreCase(mNameText.getText().trim())) {
                            CMSAdminUtil.showMessageDialog(mParentFrame, "Error",
                                mNameText.getText().trim()+" already exists",
                                CMSAdminUtil.ERROR_MESSAGE);
                            return;
                        }
                        if (mNameText.getText().trim().indexOf(' ') > -1 ||
                            mNameText.getText().trim().indexOf('.') > -1 ||
                            mNameText.getText().trim().indexOf(',') > -1) {
                            CMSAdminUtil.showMessageDialog(mParentFrame, "Error",
                                "Invalid name: "+mNameText.getText(),
                                CMSAdminUtil.ERROR_MESSAGE);
                            return;
                        }
                    }

                    mAdmin.add(mDest, ScopeDef.SC_CRLIPS,
                               mNameText.getText().trim(), nvps);
                    mNames.addElement(mNameText.getText());
                }
                this.dispose();
            } catch (EAdminException ex) {
                CMSAdminUtil.showMessageDialog(mParentFrame,
                "Error", ex.toString(), CMSAdminUtil.ERROR_MESSAGE);
            }
        } else if (e.getSource().equals(mHelp)) {
            CMSAdminUtil.help(HELPINDEX);
        }
    }
}

