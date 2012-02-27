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
package com.netscape.admin.certsrv.managecert;

import com.netscape.admin.certsrv.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;

/**
 * Certificate Information dialog
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.managecert
 */
public class CertificateInfoDialog extends JDialog
    implements ActionListener {
    private String  PREFIX = "CERTINFODIALOG";

    private JFrame mParent;
    private ResourceBundle mResource;
    private JTextArea mTextArea;
    private JLabel mCertNameField, mStatusLbl;
    private JButton mClose, mHelp, mTrust;
    private AdminConnection mConn;
    private String mCertName;
    private String mCertDate;
    private JButton mActionBtn;
    private static final String HELPINDEX = 
      "configuration-managecert-wizard-trustcert-help";

    JLabel changeLbl = null;

    public CertificateInfoDialog(JFrame parent) {
        super(parent,true);
        mParent = parent;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(650, 400);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }
 
    public void showDialog(String name, String content, String trust) {
        mCertNameField.setText(name);
        mTextArea.setText(content);
        String actionStr = "";
        String statusStr = "";
        if (trust.equals("Trust")) {
            //mTrust.setText(" Trust ");
            actionStr = mResource.getString(PREFIX+"_BUTTON_UNTRUST_LABEL"); 
            statusStr = mResource.getString(PREFIX+"_LABEL_TRUSTSTATUS_LABEL");
			mActionBtn.setText(actionStr);
			mStatusLbl.setText(statusStr);
        } else if (trust.equals("Untrust")){
            //mTrust.setText(trust);
            actionStr = mResource.getString(PREFIX+"_BUTTON_TRUST_LABEL"); 
            statusStr = mResource.getString(PREFIX+"_LABEL_UNTRUSTSTATUS_LABEL");
			mActionBtn.setText(actionStr);
			mStatusLbl.setText(statusStr);
        } else { /* user certs can't be changed */
			actionStr = mResource.getString(PREFIX+"_BUTTON_USER_LABEL");
            statusStr = mResource.getString(PREFIX+"_LABEL_USER_LABEL");
			mActionBtn.setText(actionStr);
			mActionBtn.setEnabled(false);
			mStatusLbl.setText(statusStr);
			changeLbl.setEnabled(false);
		}
        this.show();
    }
 
    public void showDialog(String name, String content, String trust,
      String date, AdminConnection conn) {
        mConn = conn;
        mCertName = name;
        mCertDate = date;
        showDialog(name, content, trust);
    }

    public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mClose)) {
            this.hide();
            this.dispose();
        } else if (evt.getSource().equals(mActionBtn)) {
            String trustLbl = mActionBtn.getText().trim();
            String trustaction = mResource.getString(PREFIX+"_BUTTON_TRUST_LABEL");
            String untrustaction = mResource.getString(PREFIX+"_BUTTON_UNTRUST_LABEL");
            String trust = "";
            if (trustLbl.equals(trustaction))
                trust = "Trust";
            else if (trustLbl.equals(untrustaction))
                trust = "Untrust";
			else // user certs not to be changable
				return;

            NameValuePairs nvps = new NameValuePairs();
            String value = mCertName+";"+mCertDate;
            nvps.put("certName0", value);
            
            try {
                mConn.modify(DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_TRUST, 
                  trust, nvps);
                String actionStr = "";
                String statusStr = "";
                if (trust.equals("Trust")) {
                    actionStr = mResource.getString(PREFIX+"_BUTTON_UNTRUST_LABEL");
                    statusStr = mResource.getString(PREFIX+"_LABEL_TRUSTSTATUS_LABEL");
                } else {
                    actionStr = mResource.getString(PREFIX+"_BUTTON_TRUST_LABEL");
                    statusStr = mResource.getString(PREFIX+"_LABEL_UNTRUSTSTATUS_LABEL");
                }

                mActionBtn.setText(actionStr);
                mStatusLbl.setText(statusStr);
            } catch (EAdminException ex) {
                CMSAdminUtil.showErrorDialog(mParent, mResource, ex.toString(),
                  CMSAdminUtil.ERROR_MESSAGE);
            }
        } else if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(HELPINDEX);
        }
    }

/*
    private void refresh() {
        try {
            NameValuePairs results = mConn.process(
              DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_CERT_PRETTY_PRINT,
              Constants.RS_ID_CONFIG, nvps);
            if (nvps.size() <= 0)
                return;
            NameValuePair nvp = results.elementAt(0);
            String name = nvp.getName();
            String value = nvp.getValue();
            CertificateInfoDialog dialog = new CertificateInfoDialog(mParent);
            dialog.showDialog(name, value);
        } catch (EAdminException ex) {
            CMSAdminUtil.showErrorDialog(mParent, mResource, ex.toString(),
              CMSAdminUtil.ERROR_MESSAGE);
        }
    }
*/

    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
 gbc.fill = gbc.BOTH;
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
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

    private JPanel makeActionPane() {
        mClose = CMSAdminUtil.makeJButton(mResource, PREFIX, "CLOSE", 
          null, this);
     
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
        Dimension d = mClose.getMinimumSize();
        if (d.width < CMSAdminUtil.DEFAULT_BUTTON_SIZE) {
            d.width = CMSAdminUtil.DEFAULT_BUTTON_SIZE;
            mClose.setMinimumSize(d);
        }
        d = mHelp.getMinimumSize();
        if (d.width < CMSAdminUtil.DEFAULT_BUTTON_SIZE) {
            d.width = CMSAdminUtil.DEFAULT_BUTTON_SIZE;
            mHelp.setMinimumSize(d);
        }
        //JButton[] buttons = {mClose, mHelp};
        JButton[] buttons = {mClose};
        return CMSAdminUtil.makeJButtonPanel( buttons );
    }

    private JPanel makeContentPane() {
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout(gb3);
        content.setBorder(CMSAdminUtil.makeTitledBorder(mResource,
          "CERTINFODIALOG", "CERT"));

        JPanel panel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        panel.setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.BOTH;
        content.add(panel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "CERTNAME",
          null);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          0, //CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(label1, gbc);
        panel.add(label1);

        CMSAdminUtil.resetGBC(gbc);
        mCertNameField = new JLabel(" ");
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.anchor = gbc.WEST;
        gbc.weightx=1.0;
        //gbc.fill = gbc.NONE;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(mCertNameField, gbc);
        panel.add(mCertNameField);


        //CMSAdminUtil.addEntryField(content, label1, mCertNameField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "CONTENT", null);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.WEST;
        //gbc.gridwidth =  gbc.REMAINDER;
        gbc.insets = new Insets(0,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(label2, gbc);
        panel.add(label2);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = new JLabel(" ");
        //gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.anchor = gbc.WEST;
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(label3, gbc);
        panel.add(label3);

        CMSAdminUtil.resetGBC(gbc);
        mTextArea = new JTextArea("",100,90);
        mTextArea.setEditable(false);
        mTextArea.setBackground(getBackground());
        JScrollPane scrollPanel = new JScrollPane(mTextArea,
                            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPanel.setAlignmentX(LEFT_ALIGNMENT);
        scrollPanel.setAlignmentY(TOP_ALIGNMENT);
        scrollPanel.setBorder(BorderFactory.createLoweredBevelBorder());
        gbc.fill = gbc.BOTH;
        gbc.gridwidth =  gbc.REMAINDER;
//        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx=1.0;
        gbc.weighty=1.0;
        gbc.insets = new Insets(0,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb3.setConstraints(scrollPanel, gbc);
        content.add(scrollPanel);

        CMSAdminUtil.resetGBC(gbc);
        mStatusLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX, "TRUSTSTATUS", null);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.insets = new Insets(0,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb3.setConstraints(mStatusLbl, gbc);
        content.add(mStatusLbl);

        CMSAdminUtil.resetGBC(gbc);
        changeLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX, "MODIFY", null);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(0,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb3.setConstraints(changeLbl, gbc);
        content.add(changeLbl);

        CMSAdminUtil.resetGBC(gbc);
        mActionBtn = CMSAdminUtil.makeJButton(mResource, PREFIX,"UNTRUST", null, this);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(0,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gbc.gridwidth =  gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.fill = gbc.NONE;
        gb3.setConstraints(mActionBtn, gbc);
        content.add(mActionBtn);
/*
        CMSAdminUtil.resetGBC(gbc);
        mTrust = CMSAdminUtil.makeJButton(mResource, PREFIX, "TRUST", null, this);
        gbc.fill = gbc.NONE;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(0,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gbc.gridwidth =  gbc.REMAINDER;
        gb3.setConstraints(mTrust, gbc);
        content.add(mTrust);
*/

        return content;
    }
}

