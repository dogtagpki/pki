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
import java.util.*;
import java.awt.event.*;

/**
 * LDAP server setting tab
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public abstract class CMSBaseLDAPPanel extends CMSBaseTab implements ItemListener {
    private static final String SERVER_CERT_NICKNAME = "Server-Cert";
    private JTextField mHostNameText;
    private JTextField mPortText;
    //private JTextField mBaseDNText;
    private JTextField mBindAsText;
    private JPasswordField mPasswordText;
    private JCheckBox mSecurePort;
    private JCheckBox mEnable;
    private JCheckBox mEnablePublishing;
    private JCheckBox mEnableQueue;
    private Color mActiveColor;
    private JLabel mHostLabel, mPortLabel, mBindAsLabel, mVersionLabel; 
    protected JLabel mPasswordLabel;
    protected AdminConnection mAdmin;
    protected CMSBaseResourceModel mModel;
    private String mServletName;
    private CMSTabPanel mParent;
    private boolean mPublishing = true;
    private boolean mLDAPPublishing = true;
    private boolean mPublishingQueue = true;
    private String mPublishingQueuePriorityLevel = "0";
    private String mMaxNumberOfPublishingThreads = "3";
    private String mPublishingQueuePageSize = "40";
    private JLabel mAuthLabel, mCertLabel;
    private JComboBox mAuthBox, mCertBox;
    private String mPanelName;
    private JComboBox mVersionBox;
    private final static String[] AUTHTYPE = {Constants.PR_BASIC_AUTH,
      Constants.PR_SSL_AUTH};

    private static final String DELIMITER = ",";

    public CMSBaseLDAPPanel(String panelName, CMSTabPanel parent) {
        this(panelName, parent, true);
        mPanelName = panelName;
    }
    
    public CMSBaseLDAPPanel(String panelName, CMSTabPanel parent, boolean flag) {
        super(panelName, parent);
        mServletName = getServletName(panelName);
        mModel = parent.getResourceModel();
        mParent = parent;
        mPublishing = flag;
        mPublishingQueue = flag;
        mLDAPPublishing = flag;
    }

    public void init() {
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel serverInfo = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);
        
        mEnablePublishing = makeJCheckBox("ENABLEPUBLISHING");
        mEnablePublishing.setSelected(true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE, 
                                DIFFERENT_COMPONENT_SPACE,
                                0,
                                DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(mEnablePublishing, gbc);
        mCenterPanel.add(mEnablePublishing);

        //add the enable queue
        mEnableQueue = makeJCheckBox("ENABLEQUEUE");
        mEnableQueue.setSelected(true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE, 
                                DIFFERENT_COMPONENT_SPACE,
                                0,
                                DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(mEnableQueue, gbc);
        mCenterPanel.add(mEnableQueue);

        //add the enable checkbox
        mEnable = makeJCheckBox("ENABLE");
        mEnable.setSelected(true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE, 
                                DIFFERENT_COMPONENT_SPACE,
                                0,
                                DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(mEnable, gbc);
        if (mLDAPPublishing)
            mCenterPanel.add(mEnable);
        
        //add the destination panel
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(serverInfo, gbc);
        mCenterPanel.add(serverInfo);

        GridBagLayout gb1 = new GridBagLayout();
        serverInfo.setLayout(gb1);
        if (mLDAPPublishing)
            serverInfo.setBorder(makeTitledBorder("DESTINATION"));
        
        // add host name label and text field
        CMSAdminUtil.resetGBC(gbc);
        mHostLabel = makeJLabel("HOST");
        mHostNameText = makeJTextField(30);
        mActiveColor = mHostNameText.getBackground();
        CMSAdminUtil.addEntryField(serverInfo, mHostLabel, mHostNameText, gbc);

        // add port number label
        CMSAdminUtil.resetGBC(gbc);
        mPortLabel = makeJLabel("PORT");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        gb1.setConstraints(mPortLabel, gbc);
        serverInfo.add(mPortLabel);

        // add port number text field
        CMSAdminUtil.resetGBC(gbc);
        mPortText = makeJTextField(10);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 0.0;
        gb1.setConstraints(mPortText, gbc);
        serverInfo.add(mPortText);

        // add check box
        CMSAdminUtil.resetGBC(gbc);
        mSecurePort = makeJCheckBox("SECUREPORT");
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE - COMPONENT_SPACE,0,COMPONENT_SPACE);
        gb1.setConstraints(mSecurePort, gbc);
        serverInfo.add(mSecurePort);

        /* add base DN label and text field
        CMSAdminUtil.resetGBC(gbc);
        JLabel baseDNLabel = makeJLabel("BASEDN");
        mBaseDNText = makeJTextField(30);
        CMSAdminUtil.addEntryField(serverInfo, baseDNLabel, mBaseDNText, gbc);
        */

        // add bind as label and text field
        CMSAdminUtil.resetGBC(gbc);
        mBindAsLabel = makeJLabel("BINDAS");
        mBindAsText = makeJTextField(30);
        CMSAdminUtil.addEntryField(serverInfo, mBindAsLabel, mBindAsText, gbc);

        // add password label and text field
        CMSAdminUtil.resetGBC(gbc);
        mPasswordLabel = makeJLabel("PWD");
        mPasswordText = makeJPasswordField(20);
        CMSAdminUtil.addEntryField(serverInfo, mPasswordLabel, mPasswordText, gbc);

        // add LDAP version
        CMSAdminUtil.resetGBC(gbc);
        mVersionLabel = makeJLabel("VERSION");
        mVersionBox = makeJComboBox("VERSION");
        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.addEntryField(serverInfo, mVersionLabel, mVersionBox,
          dummy, gbc);
        
        // add cert nickname
        CMSAdminUtil.resetGBC(gbc);
        mCertLabel = makeJLabel("CERTLIST");
        mCertBox = makeJComboBox("CERTLIST");
        JLabel dummy3 = new JLabel(" ");
        CMSAdminUtil.addEntryField(serverInfo, mCertLabel, mCertBox, dummy3, gbc);

        // add combo box for authentication type
        CMSAdminUtil.resetGBC(gbc);
        mAuthLabel = makeJLabel("AUTHTYPE");
        mAuthBox = makeJComboBox("AUTHTYPE");
        mAuthBox.addItemListener(this);
        JLabel dummy4 = new JLabel(" ");
        CMSAdminUtil.addEntryField(serverInfo, mAuthLabel, mAuthBox, dummy4, gbc);
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        if (mPublishing)
            nvps.add(Constants.PR_PUBLISHING_ENABLE,"");
        if (mLDAPPublishing)
            nvps.add(Constants.PR_ENABLE,"");
        nvps.add(Constants.PR_HOST_NAME, "");
        nvps.add(Constants.PR_LDAP_PORT, "");
        nvps.add(Constants.PR_SECURE_PORT_ENABLED, "");
        //nvps.add(Constants.PR_BASE_DN, "");
        nvps.add(Constants.PR_BIND_DN, "");
        nvps.add(Constants.PR_LDAP_VERSION, "");
        nvps.add(Constants.PR_AUTH_TYPE, "");
        nvps.add(Constants.PR_CERT_NAMES, "");
        nvps.add(Constants.PR_LDAP_CLIENT_CERT, "");

        nvps.add(Constants.PR_PUBLISHING_QUEUE_ENABLE, "");
        nvps.add(Constants.PR_PUBLISHING_QUEUE_THREADS, "");
        nvps.add(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE, "");
        nvps.add(Constants.PR_PUBLISHING_QUEUE_PRIORITY, "");

        try {
            NameValuePairs val = mAdmin.read(mServletName,
              ScopeDef.SC_LDAP, Constants.RS_ID_CONFIG, nvps);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    protected String getServletName(String panelName) {
        if (panelName.equals("LDAPSETTING")) 
            return DestDef.DEST_SERVER_ADMIN;
        else if (panelName.equals("CALDAPSETTING")) 
            return DestDef.DEST_CA_PUBLISHER_ADMIN;
        return DestDef.DEST_RA_PUBLISHER_ADMIN;
    }

    protected void populate(NameValuePairs nvps) {
        String clientCert = "";
        int serverCertIndex = -1;

        String version = "";
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_HOST_NAME)) {
                mHostNameText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_LDAP_PORT)) {
                mPortText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_SECURE_PORT_ENABLED)) {
                if (nvp.getValue().equals(Constants.TRUE))
                    mSecurePort.setSelected(true);
                else
                    mSecurePort.setSelected(false);
            } else if (name.equals(Constants.PR_BIND_DN)) {
                mBindAsText.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_PUBLISHING_ENABLE)) {
                if (nvp.getValue().equals(Constants.TRUE))
                    mEnablePublishing.setSelected(true);
                else
                    mEnablePublishing.setSelected(false);
            } else if (name.equals(Constants.PR_PUBLISHING_QUEUE_ENABLE)) {
                if (nvp.getValue().equals(Constants.TRUE)) {
                    mEnableQueue.setSelected(true);
                    mPublishingQueue = true;
                } else {
                    mEnableQueue.setSelected(false);
                    mPublishingQueue = false;
                }
            } else if (name.equals(Constants.PR_PUBLISHING_QUEUE_THREADS)) {
                mMaxNumberOfPublishingThreads = nvp.getValue();
            } else if (name.equals(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE)) {
                mPublishingQueuePageSize = nvp.getValue();
            } else if (name.equals(Constants.PR_PUBLISHING_QUEUE_PRIORITY)) {
                mPublishingQueuePriorityLevel = nvp.getValue();
            } else if (name.equals(Constants.PR_ENABLE)) {
                if (nvp.getValue().equals(Constants.TRUE))
                    mEnable.setSelected(true);
                else
                    mEnable.setSelected(false);
            } else if (name.equals(Constants.PR_AUTH_TYPE)) {
                int index = getIndex(nvp.getValue(), AUTHTYPE);
                if (index >= 0)
                    mAuthBox.setSelectedIndex(index);
            } else if (name.equals(Constants.PR_CERT_NAMES)) {
                mCertBox.removeAllItems();
                String certNames = nvp.getValue();
                StringTokenizer tokenizer = new StringTokenizer(certNames,
                  DELIMITER);
                for (int index=0; tokenizer.hasMoreTokens(); index++) {
                    String str = (String)tokenizer.nextToken();
                    if (str.startsWith(SERVER_CERT_NICKNAME))
                        serverCertIndex = index; 
                    mCertBox.addItem(str);
                }
            } else if (name.equals(Constants.PR_LDAP_CLIENT_CERT)) {
                clientCert = nvp.getValue();
            } else if (name.equals(Constants.PR_LDAP_VERSION)) {
                version = nvp.getValue();
            }
        }

        if (version.equals("")) 
            mVersionBox.setSelectedIndex(1);
        else
            mVersionBox.setSelectedItem(version);

        if (clientCert.equals("")) {
            if (serverCertIndex == -1)
                mCertBox.setSelectedIndex(0);
            else
                mCertBox.setSelectedIndex(serverCertIndex);
        } else
            mCertBox.setSelectedItem(clientCert.trim());

        if (mEnablePublishing.isSelected())
	{
            enableFieldsAndLDAP(true, mActiveColor);
	}
	else
	{
            enableFieldsAndLDAP(false, getBackground());
	}

        if (mEnable.isSelected())
            enableFields(true, mActiveColor);
        else
            enableFields(false, getBackground());

        mPasswordText.setText("");
    }

    private int getIndex(String val, String[] array) {
        for (int i=0; i<array.length; i++) {
            if (val.equals(array[i]))
                return i;
        }
        return -1;
    }

    private void enableFieldsAndLDAP(boolean enable, Color color) {
	mEnable.setEnabled(enable);
	mEnableQueue.setEnabled(enable);
	if (!enable) {
		mEnable.setSelected(false);
		mEnableQueue.setSelected(false);
	}
	enableFields(enable, color);
    }

    private void enableFields(boolean enable, Color color) {
        mHostNameText.setEnabled(enable);
        mHostNameText.setEditable(enable);
        mHostNameText.setBackground(color);
        mPortText.setEnabled(enable);
        mPortText.setEditable(enable);
        mPortText.setBackground(color);
        mPasswordText.setEnabled(enable);
        mPasswordText.setEditable(enable);
        mPasswordText.setBackground(color);
        mSecurePort.setEnabled(enable);
        mHostLabel.setEnabled(enable);
        mPortLabel.setEnabled(enable);
        mAuthBox.setEnabled(enable);
        mAuthLabel.setEnabled(enable);
        mVersionLabel.setEnabled(enable);
        mVersionBox.setEnabled(enable);
        mPasswordLabel.setEnabled(enable);
        enableAuthFields(enable, color);
    }

    private void enableAuthFields(boolean enable, Color color) {
        if (enable) {
            if (mAuthBox.getSelectedIndex() == 0) {
                mCertLabel.setEnabled(!enable);
                mCertBox.setEnabled(!enable);
                mBindAsText.setEnabled(enable);
                mBindAsText.setEditable(enable);
                mBindAsText.setBackground(color);
                mBindAsLabel.setEnabled(enable);
                mPasswordText.setEnabled(enable);
                mPasswordText.setEditable(enable);
                mPasswordText.setBackground(color);
                mPasswordLabel.setEnabled(enable);
            } else {
                mCertLabel.setEnabled(enable);
                mCertBox.setEnabled(enable);
                mBindAsText.setEnabled(!enable);
                mBindAsText.setEditable(!enable);
                mBindAsText.setBackground(getBackground());
                mBindAsLabel.setEnabled(!enable);
                mPasswordText.setEnabled(!enable);
                mPasswordText.setEditable(!enable);
                mPasswordText.setBackground(getBackground());
                mPasswordLabel.setEnabled(!enable);
            }
        } else {
            mCertLabel.setEnabled(enable);
            mCertBox.setEnabled(enable);
            mBindAsText.setEnabled(enable);
            mBindAsText.setEditable(enable);
            mBindAsText.setBackground(color);
            mBindAsLabel.setEnabled(enable);
            mPasswordText.setEnabled(enable);
            mPasswordText.setEditable(enable);
            mPasswordText.setBackground(color);
            mPasswordLabel.setEnabled(enable);
        }
        repaintComp(mHostLabel);
        repaintComp(mPortLabel);
        repaintComp(mSecurePort);
        repaintComp(mBindAsLabel);
        repaintComp(mCertLabel);
        repaintComp(mAuthLabel);
        repaintComp(mVersionLabel);
        repaintComp(mPasswordText);
        repaintComp(mPasswordLabel);
    }

    private void repaintComp(JComponent component) {
        component.invalidate();
        component.validate();
        component.repaint(1);    
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
        if (mEnablePublishing.isSelected()) {
            mEnable.setEnabled(true);
            mEnableQueue.setEnabled(true);
            enableFieldsAndLDAP(true, mActiveColor);
        } else {
            mEnable.setEnabled(false);
            mEnableQueue.setEnabled(false);
            enableFieldsAndLDAP(false, getBackground());
        }
        if (mLDAPPublishing) {
            if (mEnable.isSelected()) {
                enableFields(true, mActiveColor);
            } else {
                enableFields(false, getBackground());
            }
        }
    }

    public void itemStateChanged(ItemEvent e) {
        super.itemStateChanged(e);
        if (e.getSource().equals(mAuthBox)) {
            int index = mAuthBox.getSelectedIndex();
            if (index == 1) {
                mSecurePort.setSelected(true);
            }
            enableFields(true, mActiveColor);
        }
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        // check blank fields
        NameValuePairs nvps = new NameValuePairs();

        if (mPublishing) {
            if (mEnablePublishing.isSelected())
                nvps.add(Constants.PR_PUBLISHING_ENABLE,Constants.TRUE);
            else
                nvps.add(Constants.PR_PUBLISHING_ENABLE,Constants.FALSE);
		}

        if (mLDAPPublishing) {
            if (mEnable.isSelected())
                nvps.add(Constants.PR_ENABLE,Constants.TRUE);
            else
                nvps.add(Constants.PR_ENABLE,Constants.FALSE);
        }

        if (mEnableQueue.isSelected())
            nvps.add(Constants.PR_PUBLISHING_QUEUE_ENABLE, Constants.TRUE);
        else
            nvps.add(Constants.PR_PUBLISHING_QUEUE_ENABLE, Constants.FALSE);
        nvps.add(Constants.PR_PUBLISHING_QUEUE_THREADS, mMaxNumberOfPublishingThreads);
        nvps.add(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE, mPublishingQueuePageSize);
        nvps.add(Constants.PR_PUBLISHING_QUEUE_PRIORITY, mPublishingQueuePriorityLevel);

        if (mEnable.isSelected()) {
            String host = mHostNameText.getText().trim();
            String port = mPortText.getText().trim();
            String bindAs = mBindAsText.getText().trim();
			String passwd = null;

            if (host.equals("") || port.equals("")) {
                showMessageDialog("BLANKFIELD");
                return false;
            }

            try {
                int num = Integer.parseInt(port);
            } catch (NumberFormatException e) {
                showMessageDialog("NUMBERFORMAT");
                return false;
            }
            nvps.add(Constants.PR_HOST_NAME, host);
            nvps.add(Constants.PR_LDAP_PORT, port);

            if (mSecurePort.isSelected())
                nvps.add(Constants.PR_SECURE_PORT_ENABLED, Constants.TRUE);
            else
                nvps.add(Constants.PR_SECURE_PORT_ENABLED, Constants.FALSE);

            if (mAuthBox.getSelectedIndex() == 0) {
                if (mPanelName.equals("CALDAPSETTING")) {
                    nvps.add(Constants.PR_BINDPWD_PROMPT, "CA LDAP Publishing");
                } else {
                    nvps.add(Constants.PR_BINDPWD_PROMPT, "RA LDAP Publishing");
                }
                nvps.add(Constants.PR_BIND_DN, bindAs);
                passwd = mPasswordText.getText();

                if (passwd.equals("")) {
                    showMessageDialog("EMPTYPASSWD");
                    return false;
                }
           
                nvps.add(Constants.PR_DIRECTORY_MANAGER_PWD, passwd);
            } else {
                nvps.add(Constants.PR_LDAP_CLIENT_CERT, 
                  (String)(mCertBox.getSelectedItem()));
            }

            int index = mAuthBox.getSelectedIndex();
            if (index == 1) {
                if (!mSecurePort.isSelected()) {
                    showMessageDialog("SSLERROR");
                    return false;
                }
            }
            nvps.add(Constants.PR_AUTH_TYPE, AUTHTYPE[index]);
            nvps.add(Constants.PR_LDAP_VERSION, 
              (String)mVersionBox.getSelectedItem());

			// test the connection before save
			/*
			LDAPConnection conn = null;
			if (mAuthBox.getSelectedIndex() == 1) {
				try {
					conn = new LDAPConnection(new LdapJssSSLSocketFactory(
						(String)(mCertBox.getSelectedItem())));
					showMessageDialog("SSLOK");
				} catch (LDAPException e ) {
					showMessageDialog("SSLERROR");
				}
				try {
					conn.connect((String)mVersionBox.getSelectedItem(),
								 host, port, null, null);
				} catch (LDAPException e ) {
					showMessageDialog("SSLERROR");
				}
            } else {
				try {
					if (mSecurePort.isSelected()) {
						conn = new LDAPConnection(new
											  LdapJssSSLSocketFactory());
					} else {
						conn = new LDAPConnection();
					}
					showMessageDialog("SSLOK");
				} catch (LDAPException e ) {
					showMessageDialog("SSLERROR");
				}
				try {
					conn.connect(host, port);
					showMessageDialog("SSLOK");
				} catch (LDAPException e ) {
					showMessageDialog("SSLERROR");
				}
				try {
					conn.authenticate((String)mVersionBox.getSelectedItem(),
									  bindAs, passwd);
					showMessageDialog("SSLOK");
				} catch (LDAPException e ) {
					showMessageDialog("SSLERROR");
				}
			}
			*/
				
        }

        mModel.progressStart();
        try {
            NameValuePairs nvps1 = mAdmin.process(mServletName, ScopeDef.SC_LDAP,
								  Constants.RS_ID_CONFIG, nvps, false);
			// show test report
			String report = "";
			for (int i = 0; i<nvps1.size();i++) {
				report = report + nvps1.elementAt(i).getValue() + "\n";
			}
			if (report.indexOf("Fail") == -1) {
				JOptionPane.showMessageDialog(
				    UtilConsoleGlobals.getActivatedFrame(),
					CMSAdminUtil.wrapText(report,80),
					"Configuration Successful",
					JOptionPane.INFORMATION_MESSAGE, 
					CMSAdminUtil.getImage(CMSAdminResources.IMAGE_INFO_ICON));
				clearDirtyFlag();
			} else {
				int i = JOptionPane.showConfirmDialog(
				    UtilConsoleGlobals.getActivatedFrame(),
					CMSAdminUtil.wrapText(report,80),
					"Configuration Error", JOptionPane.YES_NO_OPTION,
					JOptionPane.ERROR_MESSAGE, 
					CMSAdminUtil.getImage(CMSAdminResources.IMAGE_ERROR_ICON));
				if (i == JOptionPane.YES_OPTION) {
					mAdmin.modify(mServletName, ScopeDef.SC_LDAP,
								  Constants.RS_ID_CONFIG, nvps, false);
					clearDirtyFlag();
				} else {
					nvps.add(Constants.PR_ENABLE, "false");
					mAdmin.modify(mServletName, ScopeDef.SC_LDAP,
								  Constants.RS_ID_CONFIG, nvps, false);
				}
			}
         } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
            return false;
        }

        mModel.progressStop();
        //clearDirtyFlag();
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

