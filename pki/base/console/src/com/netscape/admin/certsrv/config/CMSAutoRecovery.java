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

import java.awt.*;
import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.*;
import javax.swing.event.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.*;

/**
 * Display the auto recovery dialog box.
 * @author chrisho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSAutoRecovery extends JDialog implements ActionListener,
  ListSelectionListener, MouseListener {

    private final static String PREFIX = "AUTORECOVERYDIALOG";
    private AdminConnection mAdmin;
    private JFrame mParentFrame;
    private ResourceBundle mResource;
    private JButton mOK;
    private JButton mCancel;
    private JButton mEnable;
    private String mDisableLabel;
    private String mDisableTip;
    private JTable mTable;
    private AutoRecoveryModel mDataModel;
    protected JScrollPane mScrollPane;

    public CMSAutoRecovery(JFrame parent, AdminConnection conn, JButton button) {
        super(parent, true);
        mParentFrame = parent;
        mAdmin = conn;
        mEnable = button;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDisableLabel = mResource.getString(PREFIX + "_BUTTON_"+"DISABLEAUTO_LABEL");
        mDisableTip = mResource.getString(PREFIX + "_BUTTON_"+"DISABLEAUTO_TTIP");
        setSize(360, 216);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("ok")) {

            Component component = mTable.getEditorComponent();
            if(component!= null) {
                int col = mTable.getEditingColumn();
                int row = mTable.getEditingRow();
                if ((col>-1)&&(row>-1)) {
                    String str = ((JTextComponent)component).getText(); 
                    mTable.setValueAt(str, row, col);
                }
            }

            String val = getUIDPassword();

            // check empty user id and password
            if (val.equals("")) {
                CMSAdminUtil.showMessageDialog(mParentFrame, mResource,
                  PREFIX, "EMPTYFIELD", CMSAdminUtil.ERROR_MESSAGE);
                return;
            } else { 
                NameValuePairs nvps = new NameValuePairs();
                nvps.add(Constants.PR_RECOVERY_AGENT, val);
                nvps.add(Constants.PR_AUTO_RECOVERY_ON, Constants.TRUE); 
                  
                try {
                    mAdmin.modify(DestDef.DEST_KRA_ADMIN,
                      ScopeDef.SC_AUTO_RECOVERY, Constants.RS_ID_CONFIG, nvps);
                } catch (EAdminException ex) {
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                      ex.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                }
            } 
            mEnable.setText(mDisableLabel);
            mEnable.setToolTipText(mDisableTip);
            mEnable.repaint();
            cleanup();
            this.dispose();
        } else if (e.getActionCommand().equals("cancel")) {
            cleanup();
            this.dispose();
        }
      
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new DefaultTableCellRenderer());
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellEditor(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new PasswordCellRenderer());
        table.getColumnModel().getColumn(index).setCellEditor(
          new DefaultCellEditor(new JPasswordField()));
    }

    private String getUIDPassword() {
        String result = "";
        for (int i=0; i<mDataModel.getRowCount(); i++) {
            for (int j=1; j<mDataModel.getColumnCount(); j++) {
                String val = (String)mDataModel.getValueAt(i, j);
                if (val.equals(""))
                    return "";
                else if (j == (mDataModel.getColumnCount()-1))
                    result = result+val;
                else
                    result = result+val+"=";
            }
            if (i < (mDataModel.getRowCount()-1))
                result = result+",";
        }
        return result;
    }

    private void cleanup() {
        mDataModel.removeAllRows();
    }

    private void setDisplay() {
        GridBagLayout gbm = new GridBagLayout();
        getContentPane().setLayout(gbm);
        GridBagConstraints gbc = new GridBagConstraints();
     
        CMSAdminUtil.resetGBC(gbc);
        JLabel heading = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "HEADING", null);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbm.setConstraints(heading, gbc);
        getContentPane().add(heading);

        createTable();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        gbm.setConstraints(mScrollPane, gbc);
        getContentPane().add(mScrollPane);

        JPanel action = makeActionPane();

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.SOUTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbm.setConstraints(action, gbc);
        getContentPane().add(action);

        this.show();
    }

    private JPanel makeLabelPane() {
        JPanel labelPane = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        labelPane.setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel heading = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "HEADING", null);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(heading, gbc);
        labelPane.add(heading);
        return labelPane;
    }

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mOK.setActionCommand("ok");
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mCancel.setActionCommand("cancel");
        JButton[] buttons = {mOK, mCancel};
        JButtonFactory.resize(buttons);
        return CMSAdminUtil.makeJButtonPanel(buttons);
    }

    private void createTable() {
  
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_RECOVERY_M, "");

        int numUsers = 0;
        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_KRA_ADMIN,
              ScopeDef.SC_RECOVERY, Constants.RS_ID_CONFIG, nvps);
            String str = val.getValue(Constants.PR_RECOVERY_M);
            numUsers = Integer.parseInt(str);
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
        }
        
        mDataModel = new AutoRecoveryModel();
        Vector[] data = new Vector[numUsers];
        for (int i=0; i<data.length; i++) {
            data[i] = new Vector();
            Integer num = new Integer(i+1);
            data[i].addElement(num.toString());
            data[i].addElement("");
            data[i].addElement("");
            mDataModel.addRow(data[i]);
        }

        mTable = new JTable(mDataModel);
        mTable.setShowGrid(true);
        mScrollPane = JTable.createScrollPaneForTable(mTable);
        mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.setPreferredScrollableViewportSize(new Dimension(200, 100));
        //mTable.setMaximumSize(new Dimension(200, 100));
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mTable.addMouseListener((MouseListener)this);
        setLabelCellRenderer(mTable, 1);
        setLabelCellEditor(mTable, 2);
    }

    public void mouseClicked(MouseEvent e) {}
    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {}
    public void valueChanged(ListSelectionEvent e){
    }
}

