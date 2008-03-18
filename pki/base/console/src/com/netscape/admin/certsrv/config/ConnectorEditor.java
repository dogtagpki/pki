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
import com.netscape.admin.certsrv.ug.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Connector Editor
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class ConnectorEditor extends JDialog implements ActionListener, MouseListener {

    private final static String PREFIX = "CONNECTOREDITOR";
    private final static String HELPINDEX = 
      "configuration-ra-connector-editor-help";
    private final static String HELPINDEX1 =
      "configuration-overview";
    private JButton mOK, mCancel, mHelp;
    private String mName;
    private ListCertsModel mDataModel;
    // Changed by beomsuk
    //private JTextField mLocalText, mURIText, mHostText, mPortText;
    private JTextField mLocalText, mURIText, mHostText, mPortText, mTimeoutText, mNicknameText;
    // Change end
    private ResourceBundle mResource;
    private JFrame mParentFrame;
    private AdminConnection mAdmin;
    // Changed by beomsuk
    //private JLabel idLabel, uriLabel, hostLabel, portLabel;
    private JLabel idLabel, uriLabel, hostLabel, portLabel, timeoutLabel, timeunitLabel,
      nicknameLabel;
    // Change end
    private Color mActiveColor;
    private String mDest;
    private JCheckBox mEnableBox;
    private boolean mEnable = false;
    private String mInstanceName;
    private boolean mColocated;
    private JTable mCertTable;
    private JTextArea mHeading;

    public ConnectorEditor(AdminConnection admin, JFrame parent, String name,
      String dest, String instanceName, boolean colocated) {
        super(parent,true);
        mParentFrame = parent;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mAdmin = admin;
        mName = name;
        mInstanceName = instanceName;
        mDest = dest;
        mColocated = colocated;
        setSize(460, 516);
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
        gbc.fill = gbc.BOTH;
        //gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(content, gbc);
        center.add(content);

        NameValuePairs response = getCertsList(ScopeDef.SC_USERCERTSLIST);
        mDataModel.removeAllRows();
        if (response != null) {
            String[] vals = new String[response.size()];
            int i=0;
            for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
                String entry = ((String)e.nextElement()).trim();
                vals[i++] = entry;
            }

            int sindex = 0;
            String snickname = "";
            CMSAdminUtil.quickSort(vals, 0, response.size()-1);
            for (i=0; i<vals.length; i++) {
                Vector v = new Vector();
                String entry = vals[i];
                String value = response.getValue(entry);

                // look for the comma separator
                int lastindex = entry.lastIndexOf(",");
                if (lastindex != -1) {
                    String fullnickname = entry.substring(0, lastindex);
                    int tindex = fullnickname.indexOf(":");
                    String tokenname = fullnickname.substring(0, tindex);
                    String nickname = fullnickname.substring(tindex+1);
                    if (mName.equals("Data Recovery Manager Connector")) {
                        if (fullnickname.indexOf("subsystemCert") > -1) {
                            sindex = i;
                            snickname = fullnickname;
                        }
                    } else {
                        if (fullnickname.indexOf("raSigningCert") > -1) {
                            sindex = i;
                            snickname = fullnickname;
                        }
                    }
                    v.addElement(nickname);
                    v.addElement(entry.substring(lastindex+1));
                    v.addElement(value);
                    v.addElement(tokenname);
                    mDataModel.addRow(v);
                }
            }
            mCertTable.setRowSelectionInterval(sindex, sindex);
            mNicknameText.setText(snickname);
        }

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

    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new DefaultTableCellRenderer());
    }

    private void displayCert(int row) {
        String nickname = (String)(mCertTable.getValueAt(row, 3)) + ":" +
          (String)(mCertTable.getValueAt(row, 0));
        String serialno = (String)(mCertTable.getValueAt(row, 1));
        String issuername = (String)(mCertTable.getValueAt(row, 2));

        try {
            NameValuePairs nvps = new NameValuePairs();
            nvps.add(Constants.PR_NICK_NAME, nickname);
            nvps.add(Constants.PR_SERIAL_NUMBER, serialno);
            nvps.add(Constants.PR_ISSUER_NAME, issuername);
            NameValuePairs results = mAdmin.process(
              DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_CERT_PRETTY_PRINT,
              Constants.RS_ID_CONFIG, nvps);
            if (nvps.size() <= 0)
                return;
            NameValuePair nvp = results.elementAt(0);
            String name = nvp.getName();
            String print = nvp.getValue();
            CertViewDialog certdialog = new CertViewDialog(mParentFrame);
            certdialog.showDialog(nickname, print);
        } catch (EAdminException ex) {
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource, ex.toString(),
              CMSAdminUtil.ERROR_MESSAGE);
        }
    }

    public void mouseClicked(MouseEvent e) {
        //setButtons();

        //we track the double click action on the table entry - View op
        int row = mCertTable.getSelectedRow();
        if(row >= 0) {
            mNicknameText.setText((String)(mCertTable.getValueAt(row, 0)));
            if(e.getClickCount() == 2) {
                displayCert(row);
            }
        }
    }

    public void mouseReleased(MouseEvent e) {
    }

    public void mousePressed(MouseEvent e) {
    }

    public void mouseEntered(MouseEvent e) {
    }

    public void mouseExited(MouseEvent e) {
    }

    public void showDialog(NameValuePairs values) {

        for (int i=0; i<values.size(); i++) {
            NameValuePair nvp = values.elementAt(i);
            String name = nvp.getName();
            String val = nvp.getValue();
            if (name.equals(Constants.PR_HOST)) {
                mHostText.setText(val);
            } else if (name.equals(Constants.PR_PORT)) {
                mPortText.setText(val);
            // Inserted by beomsuk            
            } else if (name.equals(Constants.PR_TIMEOUT)) {
                if (val == null || val.equals(""))
                    mTimeoutText.setText("30");
                else
                    mTimeoutText.setText(val);
            // Insert end
            } else if (name.equals(Constants.PR_ENABLED)) {
                if (val.equals(Constants.TRUE))
                    mEnable = true;
                else
                    mEnable = false;
            }
        }

        mEnableBox.setSelected(mEnable);
        enableConnector();
        //update(local);
        this.show();
    }

    private void enableConnector() {
        if (mEnable) {
            update();
        } else {
            hostLabel.setEnabled(false);
            portLabel.setEnabled(false);
            nicknameLabel.setEnabled(false);
            timeoutLabel.setEnabled(false);
            //timeunitLabel.setEnabled(false);
            mHostText.setBackground(getBackground());
            mPortText.setBackground(getBackground());
            mNicknameText.setBackground(getBackground());
            mTimeoutText.setBackground(getBackground());
            mHostText.setEnabled(false);
            mPortText.setEnabled(false);
            mNicknameText.setEnabled(false);
            mTimeoutText.setEnabled(false);
            mHostText.setEditable(false);
            mPortText.setEditable(false);
            mNicknameText.setEditable(false);
            mTimeoutText.setEditable(false);
            mHeading.setEnabled(false);
            mCertTable.setEnabled(false);
            mCertTable.setBackground(getBackground());
            CMSAdminUtil.repaintComp(hostLabel);
            CMSAdminUtil.repaintComp(portLabel);
            CMSAdminUtil.repaintComp(timeoutLabel);
            //CMSAdminUtil.repaintComp(timeunitLabel);
            CMSAdminUtil.repaintComp(mHostText);
            CMSAdminUtil.repaintComp(mPortText);
            CMSAdminUtil.repaintComp(mTimeoutText);
        }
    }

    private void update() {
        hostLabel.setEnabled(true);
        portLabel.setEnabled(true);
        nicknameLabel.setEnabled(true);
        timeoutLabel.setEnabled(true);
        mHostText.setEditable(true);
        mPortText.setEditable(true);
        mNicknameText.setEditable(true);
        mTimeoutText.setEditable(true);
        mHostText.setBackground(mActiveColor);
        mPortText.setBackground(mActiveColor);
        mNicknameText.setBackground(mActiveColor);
        mTimeoutText.setBackground(mActiveColor);
        mHostText.setEnabled(true);
        mPortText.setEnabled(true);
        mTimeoutText.setEnabled(true);
        mNicknameText.setEnabled(true);
        mHeading.setEnabled(true);
        mCertTable.setEnabled(true);
        mCertTable.setBackground(mActiveColor);

        CMSAdminUtil.repaintComp(hostLabel);
        CMSAdminUtil.repaintComp(portLabel);
        CMSAdminUtil.repaintComp(timeoutLabel);
        //CMSAdminUtil.repaintComp(timeunitLabel);
        CMSAdminUtil.repaintComp(mHostText);
        CMSAdminUtil.repaintComp(mPortText);
        CMSAdminUtil.repaintComp(mTimeoutText);
    }

    private JPanel makeContentPanel() {
        JPanel mainPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mainPanel.setLayout(gb);

/*
        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "CONNECTORNAME", null);
        gbc.anchor = gbc.WEST;
        //gbc.weightx = 1.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(label1, gbc);
        mainPanel.add(label1);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = new JLabel(mName);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                                0, CMSAdminUtil.COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 0.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(label2, gbc);
        mainPanel.add(label2);
*/

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = new JLabel(mName+":");
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        gb.setConstraints(label2, gbc);
        mainPanel.add(label2);

        CMSAdminUtil.resetGBC(gbc);
        mEnableBox = CMSAdminUtil.makeJCheckBox(mResource, PREFIX,
          "ENABLE", null, false, this);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
/*
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE);
*/
        gb.setConstraints(mEnableBox, gbc);
        mainPanel.add(mEnableBox);

        CMSAdminUtil.resetGBC(gbc);
        hostLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "HOST", null);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(hostLabel, gbc);
        mainPanel.add(hostLabel);

        CMSAdminUtil.resetGBC(gbc);
        mHostText = new JTextField(20);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
/*
        gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
*/
        gb.setConstraints(mHostText, gbc);
        mainPanel.add(mHostText);
        mActiveColor = mHostText.getBackground();

        CMSAdminUtil.resetGBC(gbc);
        portLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "PORT", null);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gb.setConstraints(portLabel, gbc);
        mainPanel.add(portLabel);

        CMSAdminUtil.resetGBC(gbc);
        mPortText = new JTextField(20);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
/*
        gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
*/
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gb.setConstraints(mPortText, gbc);
        mainPanel.add(mPortText);

        CMSAdminUtil.resetGBC(gbc);
        timeoutLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "TIMEOUT", null);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 4*CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gbc.weightx = 0.0;
        gb.setConstraints(timeoutLabel, gbc);
        mainPanel.add(timeoutLabel);

        CMSAdminUtil.resetGBC(gbc);
        mTimeoutText = new JTextField(20);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
/*
        gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
*/
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gb.setConstraints(mTimeoutText, gbc);
        mTimeoutText.setText("30");
        mainPanel.add(mTimeoutText);

        CMSAdminUtil.resetGBC(gbc);
        nicknameLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "NICKNAME", null);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.insets = new Insets(0, CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(nicknameLabel, gbc);
        mainPanel.add(nicknameLabel);

        CMSAdminUtil.resetGBC(gbc);
        mNicknameText = new JTextField(50);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(mNicknameText, gbc);
        mainPanel.add(mNicknameText);

        CMSAdminUtil.resetGBC(gbc);
        mHeading = createTextArea(mResource.getString(
          PREFIX+"_TEXT_CERTHEADING_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        gbc.insets = new Insets(2*CMSAdminUtil.COMPONENT_SPACE, 
          4*CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(mHeading, gbc);
        mainPanel.add(mHeading);
        
        CMSAdminUtil.resetGBC(gbc);
        mDataModel = new ListCertsModel();
        mCertTable = new JTable(mDataModel);
        JScrollPane scrollPane = JTable.createScrollPaneForTable(mCertTable);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mCertTable.setPreferredScrollableViewportSize(new Dimension(200, 350));
        mCertTable.setAutoscrolls(true);
        mCertTable.sizeColumnsToFit(true);
        mCertTable.addMouseListener(this);
        scrollPane.setBackground(Color.white);
        setLabelCellRenderer(mCertTable, 0);
        setLabelCellRenderer(mCertTable, 1);
        setLabelCellRenderer(mCertTable, 2);

/*
        Vector v = new Vector();
        v.addElement("abc1");
        v.addElement("def1");
        v.addElement("hij1");
        mDataModel.addRow(v);
        Vector v1 = new Vector();
        v1.addElement("abc1");
        v1.addElement("def1");
        v1.addElement("hij1");
        mDataModel.addRow(v1);
        Vector v2 = new Vector();
        v2.addElement("abc1");
        v2.addElement("def1");
        v2.addElement("hij1");
        mDataModel.addRow(v2);
*/

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          4*CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(scrollPane, gbc);
        mainPanel.add(scrollPane);


        return mainPanel;
    }

    private JTextArea createTextArea(String str) {
        JTextArea desc = new JTextArea(str);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);

        return desc;
    }

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
        JButton[] buttons = { mOK, mCancel, mHelp};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    public void actionPerformed(ActionEvent e) {
        
        if (e.getSource().equals(mEnableBox)) {
            mEnable = mEnableBox.isSelected();
            enableConnector();
        } else if (e.getSource().equals(mCancel)) 
            this.dispose();
        else if (e.getSource().equals(mOK)) {
            NameValuePairs nvps = new NameValuePairs();
            
            if (mEnable) {
                nvps.add(Constants.PR_LOCAL, Constants.FALSE);
                nvps.add(Constants.PR_HOST, mHostText.getText());
                String portStr = mPortText.getText().trim();
                try {
                    int port = Integer.parseInt(portStr);
                    if (port <= 0) {
                        CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                          "OUTOFRANGE", CMSAdminUtil.ERROR_MESSAGE);
                        return;
                    }
                } catch (NumberFormatException ex) {
                    CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX, 
                      "NONINTEGER", CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                nvps.add(Constants.PR_PORT, portStr);

                String timeoutStr = mTimeoutText.getText().trim();
                try {
                    int timeout = Integer.parseInt(timeoutStr);
                    if (timeout < 0) {
                        CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                          "TIMEOUTOUTOFRANGE", CMSAdminUtil.ERROR_MESSAGE);
                        return;
                    }
                } catch (NumberFormatException ex) {
                    CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX, 
                      "TIMEOUTNONINTEGER", CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                nvps.add(Constants.PR_TIMEOUT, timeoutStr);
                   
                if (mName.equals("Data Recovery Manager Connector")) {
                    nvps.add(Constants.PR_URI, "/kra/agent/kra/connector");
                } else if (mName.equals("Registration Manager Connector")) {
                    nvps.add(Constants.PR_URI, "/ra/connector");
                } else if (mName.equals("Certificate Manager Connector")) {
                    nvps.add(Constants.PR_URI, "/ca/connector");
                }
                nvps.add(Constants.PR_NICK_NAME, mNicknameText.getText().trim());
                nvps.add(Constants.PR_ENABLED, Constants.TRUE);
            } else {
                nvps.add(Constants.PR_ENABLED, Constants.FALSE);
            }

            try {
                mAdmin.modify(mDest, ScopeDef.SC_CONNECTOR,
                  mName, nvps);
                this.dispose();
            } catch (EAdminException ex) {
                        CMSAdminUtil.showMessageDialog(mParentFrame, 
			"Error", ex.toString(), CMSAdminUtil.ERROR_MESSAGE);
            }
        } else if (e.getSource().equals(mHelp)) {
            CMSAdminUtil.help(HELPINDEX1);
        }
    }

    private NameValuePairs getCertsList(String scope) {
        try {
            NameValuePairs nvps = 
              mAdmin.search(DestDef.DEST_SERVER_ADMIN, scope, new NameValuePairs());
            return nvps;
        } catch (EAdminException ex) {
            CMSAdminUtil.showMessageDialog(mParentFrame, 
	      "Error", ex.toString(), CMSAdminUtil.ERROR_MESSAGE);
            return null;
        }
    }
}

