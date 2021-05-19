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
import java.util.StringTokenizer;

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
 * Panel Setting CRL Format
 *
 * @author Andrew Wnuk
 * @version $Revision$, $Date$
 */
public class CMSCRLFormatPanel extends CMSBaseTab {

    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "CRLFORMAT";
    private JCheckBox mEnableExtensions;
    private JCheckBox mEnableExpired;
    private JCheckBox mEnableOneExtraTime;
    private JCheckBox mCACertsOnly;
    private JCheckBox mProfileCertsOnly;
    private JTextField mProfiles;
    private AdminConnection _admin;
    private CMSBaseResourceModel _model;
    private JComboBox<String> mAlgorithms;
    private Color mActiveColor;
    private CMSTabPanel mParent;
    private String mId = null;
    private static final String HELPINDEX =
        "configuration-ca-ldappublish-crl-help";
    private boolean mCacheEnabled;
    private boolean mInitialized = false;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSCRLFormatPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        _model = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public CMSCRLFormatPanel(CMSTabPanel parent, String id) {
        super(PANEL_NAME, parent);
        _model = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
        mId = id;
    }

    /*==========================================================
     * public methods
     *==========================================================*/
    @Override
    public void init() {
        Debug.println("CRLFormatPanel: init()");
        _admin = _model.getServerInfo().getAdmin();

        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mCenterPanel.setLayout(gb);


        //format panel
        JPanel formatPanel = new JPanel();
        formatPanel.setBorder(makeTitledBorder("FORMAT"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gb.setConstraints(formatPanel, gbc);
        mCenterPanel.add(formatPanel);

        GridBagLayout gb1 = new GridBagLayout();
        formatPanel.setLayout(gb1);


        // algorithm selection
        CMSAdminUtil.resetGBC(gbc);
        JLabel digestLabel = makeJLabel("MESSAGEDIGEST");
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        formatPanel.add(digestLabel, gbc );

        mAlgorithms = makeJComboBox();
        mAlgorithms.addItemListener(this);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        formatPanel.add(mAlgorithms, gbc);


        // allow extensions
        CMSAdminUtil.resetGBC(gbc);
        JLabel allowExtensionsLabel = makeJLabel("EXT");
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        formatPanel.add(allowExtensionsLabel, gbc );

        mEnableExtensions = makeJCheckBox();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx++;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,COMPONENT_SPACE);
        formatPanel.add(mEnableExtensions, gbc);


        //contents panel
        JPanel contentsPanel = new JPanel();
        contentsPanel.setBorder(makeTitledBorder("CONTENTS"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(contentsPanel, gbc);
        mCenterPanel.add(contentsPanel);

        GridBagLayout gb2 = new GridBagLayout();
        contentsPanel.setLayout(gb2);


        // include expired certs
        CMSAdminUtil.resetGBC(gbc);
        mEnableExpired = makeJCheckBox("EXPIRED");
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        contentsPanel.add(mEnableExpired, gbc);


        // include expired certs one extra time
        CMSAdminUtil.resetGBC(gbc);
        mEnableOneExtraTime = makeJCheckBox("ONEEXTRATIME");
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        contentsPanel.add(mEnableOneExtraTime, gbc);


        // CA certs only
        CMSAdminUtil.resetGBC(gbc);
        mCACertsOnly = makeJCheckBox("CACERTSONLY");
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        contentsPanel.add(mCACertsOnly, gbc);


        // profile certs only
        CMSAdminUtil.resetGBC(gbc);
        mProfileCertsOnly = makeJCheckBox("PROFILECERTSONLY");
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        contentsPanel.add(mProfileCertsOnly, gbc);

        mProfiles = makeJTextField(20);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx++;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,0,0,COMPONENT_SPACE);
        contentsPanel.add(mProfiles, gbc);
        mActiveColor = mProfiles.getBackground();


        refresh();
        mInitialized = true;
    }

    @Override
    public void refresh() {
        _model.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.put(Constants.PR_EXTENSIONS, "");
        nvps.put(Constants.PR_SIGNING_ALGORITHM, "");
        nvps.put(Constants.PR_INCLUDE_EXPIREDCERTS, "");
        nvps.put(Constants.PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME, "");
        nvps.put(Constants.PR_CA_CERTS_ONLY, "");
        nvps.put(Constants.PR_PROFILE_CERTS_ONLY, "");
        nvps.put(Constants.PR_PROFILE_LIST, "");
        nvps.put(Constants.PR_ENABLE_CACHE, "");

        try {
            NameValuePairs val = null;
            if (mId != null && mId.length() > 0) {
                val = _admin.read(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                                  mId, nvps);
            } else {
                val = _admin.read(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                                  Constants.RS_ID_CONFIG, nvps);
            }

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            _model.progressStop();
        }
        _model.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();

        if (mProfileCertsOnly.isSelected()) {
            CMSAdminUtil.enableJTextField(mProfiles, true, mActiveColor);
        } else {
            CMSAdminUtil.enableJTextField(mProfiles, false, getBackground());
        }
        mEnableOneExtraTime.setEnabled(mCacheEnabled && (!mEnableExpired.isSelected()));
        CMSAdminUtil.repaintComp(mEnableOneExtraTime);
    }

    public void populate(NameValuePairs nvps) {
        String signingAlg = "";
        for (String name : nvps.keySet()) {
            String value = nvps.get(name).trim();
            if (name.equals(Constants.PR_EXTENSIONS)) {
                mEnableExtensions.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_SIGNING_ALGORITHM)) {
                signingAlg = value;
            } else if (name.equals(Constants.PR_ALL_ALGORITHMS)) {
                initAlgorithmBox(value);
            } else if (name.equals(Constants.PR_INCLUDE_EXPIREDCERTS)) {
                mEnableExpired.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME)) {
                mEnableOneExtraTime.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_CA_CERTS_ONLY)) {
                mCACertsOnly.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_PROFILE_CERTS_ONLY)) {
                mProfileCertsOnly.setSelected(getBoolean(value));
            } else if (name.equals(Constants.PR_PROFILE_LIST)) {
                mProfiles.setText(value);
            } else if (name.equals(Constants.PR_ENABLE_CACHE)) {
                mCacheEnabled = (value.equals(Constants.TRUE))? true: false;
            }
        }

        mAlgorithms.setSelectedItem(signingAlg);
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

    public boolean getBoolean(String val) {
        if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    private String trimList(String list) {
        String trimmed = "";

        StringTokenizer elements = new StringTokenizer(list, ",", true);
        int n = 0;
        while (elements.hasMoreTokens()) {
            String element = elements.nextToken().trim();
            if (element == null || element.length() == 0) return null;
            if (element.equals(",") && n % 2 == 0) return null;
            trimmed += element;
            n++;
        }
        if (n % 2 == 0) return null;

        return trimmed;
    }

    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    @Override
    public boolean applyCallback() {
        NameValuePairs nvps = new NameValuePairs();

        if (mEnableExtensions.isSelected())
            nvps.put(Constants.PR_EXTENSIONS, Constants.TRUE);
        else
            nvps.put(Constants.PR_EXTENSIONS, Constants.FALSE);

        if (mEnableExpired.isSelected())
            nvps.put(Constants.PR_INCLUDE_EXPIREDCERTS, Constants.TRUE);
        else
            nvps.put(Constants.PR_INCLUDE_EXPIREDCERTS, Constants.FALSE);

        if (mEnableOneExtraTime.isSelected())
            nvps.put(Constants.PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME, Constants.TRUE);
        else
            nvps.put(Constants.PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME, Constants.FALSE);

        if (mCACertsOnly.isSelected())
            nvps.put(Constants.PR_CA_CERTS_ONLY, Constants.TRUE);
        else
            nvps.put(Constants.PR_CA_CERTS_ONLY, Constants.FALSE);

        if (mProfileCertsOnly.isSelected())
            nvps.put(Constants.PR_PROFILE_CERTS_ONLY, Constants.TRUE);
        else
            nvps.put(Constants.PR_PROFILE_CERTS_ONLY, Constants.FALSE);

        String profileList = null;
        if (mProfileCertsOnly.isSelected()) {
            if (mProfiles.getText().trim().equals("")) {
                showMessageDialog("BLANKPROFILELIST");
                return false;
            }
            profileList = trimList(mProfiles.getText());
            if (profileList == null) {
                showMessageDialog("PROFILELISTFORMAT");
                return false;
            }
        }
        if (profileList != null)
            nvps.put(Constants.PR_PROFILE_LIST, profileList);
        else
            nvps.put(Constants.PR_PROFILE_LIST, mProfiles.getText().trim());


        nvps.put(Constants.PR_SIGNING_ALGORITHM,
                (String) mAlgorithms.getSelectedItem());

        _model.progressStart();

        try {
            if (mId != null && mId.length() > 0) {
                _admin.modify(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                              mId, nvps);
            } else {
                _admin.modify(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRL,
                              Constants.RS_ID_CONFIG, nvps);
            }
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            _model.progressStop();
            return false;
        }

        _model.progressStop();
        clearDirtyFlag();
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

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mProfileCertsOnly)) {
            if (mProfileCertsOnly.isSelected()) {
                CMSAdminUtil.enableJTextField(mProfiles, true, mActiveColor);
            } else {
                CMSAdminUtil.enableJTextField(mProfiles, false, getBackground());
            }
        } else if (e.getSource().equals(mEnableExpired)) {
            mEnableOneExtraTime.setEnabled(mCacheEnabled && (!mEnableExpired.isSelected()));
            CMSAdminUtil.repaintComp(mEnableOneExtraTime);
        }

        super.actionPerformed(e);
    }

    public void setCacheEnabled (boolean cacheEnabled) {
        if (mCacheEnabled != cacheEnabled) {
            mCacheEnabled = cacheEnabled;
            if (mInitialized) {
                mEnableOneExtraTime.setEnabled(mCacheEnabled && (!mEnableExpired.isSelected()));
                CMSAdminUtil.repaintComp(mEnableOneExtraTime);
            }
        }
    }

    /**
    * Override the initialize method only for this panel.
    * We need to refresh in case the CRLDistributionPointExtension
    * has modified the caCertsOnly property for us.
    **/
    @Override
    public void initialize() {
        Debug.println("CMSCRLFormatPanel: intialize()");
        if (!mInit) {
            init();
            mInit = true;
        } else {
            if(!isDirty()) {
                refresh();
            }
        }
    }
}

