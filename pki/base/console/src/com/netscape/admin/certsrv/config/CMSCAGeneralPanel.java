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
 * RA General Setting
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSCAGeneralPanel extends CMSBaseTab implements ItemListener {

    private static String PANEL_NAME = "CAGENERAL";
    private static CMSBaseResourceModel mModel;
    protected AdminConnection mAdmin;
    private JCheckBox mRAEnable;
    private JCheckBox mEEEnable;
    private JCheckBox mOCSPEnable;
    private CMSTabPanel mParent;
    private JComboBox mGroups;
    private JComboBox mAlgorithms;
    private JTextField mSerialNumber;
    private JTextField mMaxSerialNumber;
    private JCheckBox mValidity;
    private Vector mGroupData;
    private static final String HELPINDEX =
      "configuration-ca-general-help";

    public CMSCAGeneralPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = parent.getResourceModel();
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    public void init() {
        Debug.println("CMSCAGeneral: init()");
        mAdmin = mModel.getServerInfo().getAdmin();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);

        JPanel adminPanel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        adminPanel.setLayout(gb1);
        adminPanel.setBorder(makeTitledBorder("INTERACTION"));

        JPanel signingPanel = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        signingPanel.setLayout(gb2);
        signingPanel.setBorder(makeTitledBorder("SIGNING"));

        JPanel serialPanel = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        serialPanel.setLayout(gb3);
        serialPanel.setBorder(makeTitledBorder("SERIAL"));

        JPanel validityPanel = new JPanel();
        GridBagLayout gb4 = new GridBagLayout();
        validityPanel.setLayout(gb4);
        validityPanel.setBorder(makeTitledBorder("VALIDITY"));

        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gb.setConstraints(adminPanel, gbc);
       // mCenterPanel.add(adminPanel);
        
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(validityPanel, gbc);
        mCenterPanel.add(validityPanel);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(serialPanel, gbc);
        mCenterPanel.add(serialPanel);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(signingPanel, gbc);
        mCenterPanel.add(signingPanel);

        CMSAdminUtil.resetGBC(gbc);
        mEEEnable = makeJCheckBox("EE");
        gbc.anchor = gbc.NORTHWEST;
        // gbc.gridwidth = gbc.REMAINDER;
        // gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb1.setConstraints(mEEEnable, gbc);
        adminPanel.add(mEEEnable);

        CMSAdminUtil.resetGBC(gbc);
        mOCSPEnable = makeJCheckBox("OCSP");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb1.setConstraints(mOCSPEnable, gbc);
        adminPanel.add(mOCSPEnable);

		// add validity block
        CMSAdminUtil.resetGBC(gbc);
        mValidity = makeJCheckBox("VALIDITY");
        gbc.anchor = gbc.CENTER;
        //gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        //gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb4.setConstraints(mValidity, gbc);
        validityPanel.add(mValidity);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy4 = new JLabel(" ");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb4.setConstraints(dummy4, gbc);
        validityPanel.add(dummy4);

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

        // add serial number block
        CMSAdminUtil.resetGBC(gbc);
        JLabel serialLabel = makeJLabel("SERIAL");
        gbc.anchor = gbc.CENTER;
        gb3.setConstraints(serialLabel, gbc);
        gbc.weighty = 1.0;
        //gbc.insets = new Insets(COMPONENT_SPACE,0,COMPONENT_SPACE,0);
        serialPanel.add(serialLabel);

        CMSAdminUtil.resetGBC(gbc);
        mSerialNumber = makeJTextField(17);
        mSerialNumber.setEnabled(false);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        //gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb3.setConstraints(mSerialNumber, gbc);
        serialPanel.add(mSerialNumber);

        // add end serial number block
        CMSAdminUtil.resetGBC(gbc);
        JLabel maxSerialLabel = makeJLabel("MAXSERIAL");
        gbc.anchor = gbc.EAST;
        //gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gb3.setConstraints(maxSerialLabel, gbc);
        //gbc.weighty = 1.0;
        serialPanel.add(maxSerialLabel);

        CMSAdminUtil.resetGBC(gbc);
        mMaxSerialNumber = makeJTextField(17);
        mMaxSerialNumber.setEnabled(false);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridy = 1;
        //gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        //gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb3.setConstraints(mMaxSerialNumber, gbc);
        serialPanel.add(mMaxSerialNumber);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy2 = new JLabel(" ");
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb3.setConstraints(dummy2, gbc);
        serialPanel.add(dummy2);

        refresh();
    }

    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_EE_ENABLED, "");
        //nvps.add(Constants.PR_RA_ENABLED, "");
        nvps.add(Constants.PR_DEFAULT_ALGORITHM, "");
        nvps.add(Constants.PR_ALL_ALGORITHMS, "");
        nvps.add(Constants.PR_SERIAL, "");
        nvps.add(Constants.PR_MAXSERIAL, "");
        nvps.add(Constants.PR_VALIDITY, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_CA_ADMIN,
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
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_EE_ENABLED)) {
                mEEEnable.setSelected(getBoolean(nvp.getValue()));
            } else if (name.equals(Constants.PR_OCSP_ENABLED)) {
                mOCSPEnable.setSelected(getBoolean(nvp.getValue()));
/*
            } else if (name.equals(Constants.PR_RA_ENABLED)) {
                mRAEnable.setSelected(getBoolean(nvp.getValue()));
*/
            } else if (name.equals(Constants.PR_VALIDITY)) {
                mValidity.setSelected(getBoolean(nvp.getValue()));
            } else if (name.equals(Constants.PR_DEFAULT_ALGORITHM)) {
                defaultAlgorithm = nvp.getValue();
            } else if (name.equals(Constants.PR_ALL_ALGORITHMS)) {
                initAlgorithmBox(nvp.getValue());
            } else if (name.equals(Constants.PR_SERIAL)) {
				String serial = nvp.getValue();
				if (!serial.equals(""))
					mSerialNumber.setText(serial);
				else
					mSerialNumber.setText("All serial numbers are used");
            } else if (name.equals(Constants.PR_MAXSERIAL)) {
				String serial = nvp.getValue();
				if (!serial.equals(""))
					mMaxSerialNumber.setText(serial);
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

        if (mEEEnable.isSelected())
            nvps.add(Constants.PR_EE_ENABLED, Constants.TRUE);
        else
            nvps.add(Constants.PR_EE_ENABLED, Constants.FALSE);

        if (mOCSPEnable.isSelected())
            nvps.add(Constants.PR_OCSP_ENABLED, Constants.TRUE);
        else
            nvps.add(Constants.PR_OCSP_ENABLED, Constants.FALSE);

/*
        if (mRAEnable.isSelected())
            nvps.add(Constants.PR_RA_ENABLED, Constants.TRUE);
        else
            nvps.add(Constants.PR_RA_ENABLED, Constants.FALSE);
*/

        if (mValidity.isSelected())
            nvps.add(Constants.PR_VALIDITY, Constants.TRUE);
        else
            nvps.add(Constants.PR_VALIDITY, Constants.FALSE);

        nvps.add(Constants.PR_DEFAULT_ALGORITHM, 
          (String)mAlgorithms.getSelectedItem());

        String serial = (String)mSerialNumber.getText().trim();
        try {
			//if (serial.startsWith("0x")) {
			serial = hexToDecimal(serial);
			//}
            BigInteger num = new BigInteger(serial);
            if (num.compareTo(new BigInteger("0")) < 0) {
                showMessageDialog("OUTOFRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }
//        nvps.add(Constants.PR_SERIAL, serial);

        String maxserial =
			(String)mMaxSerialNumber.getText().trim();
		if (maxserial != null && !maxserial.equals("")) {
			try {
				//if (serial.startsWith("0x")) {
				String maxserialdec = hexToDecimal(maxserial);
				//}
				BigInteger num = new BigInteger(maxserialdec);
				if (num.compareTo(new BigInteger("0")) < 0) {
					showMessageDialog("OUTOFRANGE");
					return false;
				}
			} catch (NumberFormatException e) {
				showMessageDialog("NUMBERFORMAT");
				return false;
			}
//			nvps.add(Constants.PR_MAXSERIAL, maxserial);
		}

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_CA_ADMIN,
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
