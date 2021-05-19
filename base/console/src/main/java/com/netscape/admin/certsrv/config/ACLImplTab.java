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
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.LabelCellRenderer;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.ug.CMSBaseUGTab;
import com.netscape.admin.certsrv.ug.CMSUGTabPanel;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * ACL Implementation Tab
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class ACLImplTab extends CMSBaseUGTab {
    private static String PANEL_NAME = "ACLIMPL";
    private CMSBaseResourceModel mModel;
    private AdminConnection mConnection;
    private JTable mTable;
    private JScrollPane mScrollPane;
    protected ACLImplDataModel mDataModel;
    protected EvaluatorRegisterDialog mEditor=null;
    protected JButton mRefresh, mAdd, mDelete, mHelp;
    private static final String HELPINDEX =
      "configuration-authorization";

    public ACLImplTab(CMSUGTabPanel parent) {
        super(PANEL_NAME, parent.getResourceModel());
        mModel = parent.getResourceModel();
        mDataModel = new ACLImplDataModel();
        mConnection = mModel.getServerInfo().getAdmin();
        mHelpToken = HELPINDEX;
    }

    @Override
    protected JPanel createListPanel() {
        JPanel mainPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mainPanel.setLayout(gb);

        //center table
        mTable = new JTable(mDataModel);
        mScrollPane = new JScrollPane(mTable);
        mScrollPane.setHorizontalScrollBarPolicy(
          ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(
          ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.doLayout();
        mTable.getSelectionModel().setSelectionMode(
          ListSelectionModel.SINGLE_SELECTION);
        mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mTable.addMouseListener(this);
        setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        mainPanel.add(mScrollPane);

        JPanel buttonPanel = createButtonPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(buttonPanel, gbc);
        mainPanel.add(buttonPanel);

        refresh();

        return mainPanel;
    }

    /**
     * create the user action button panel
     */
    protected JPanel createButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
        JButton[] buttons = {mAdd, mDelete};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    @Override
    protected JPanel createActionPanel() {
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        //JButton[] buttons = { mRefresh, mHelp };
        JButton[] buttons = { mRefresh };
        return makeJButtonPanel(buttons, true);
    }

    @Override
    public void refresh() {
        mModel.progressStart();
        mDataModel.removeAllRows();
        update();
        mTable.invalidate();
        mTable.validate();
        mScrollPane.invalidate();
        mScrollPane.validate();
        mScrollPane.repaint(1);
        mModel.progressStop();
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            refresh();
        } else if (e.getSource().equals(mAdd)) {
            if (mEditor==null)
                mEditor = new EvaluatorRegisterDialog(mModel.getFrame(),
                  mConnection);
            mEditor.showDialog(DestDef.DEST_ACL_ADMIN, ScopeDef.SC_ACL_IMPLS);
            refresh();
        } else if (e.getSource().equals(mDelete)) {
            Debug.println("Delete");
            if(mTable.getSelectedRow()< 0)
                return;
            int i = showConfirmDialog("DELETE");
            if (i == JOptionPane.YES_OPTION) {
                delete();
                Debug.println("Deleted");
            }
        } else if (e.getSource().equals(mHelp)) {
            helpCallback();
        }
    }

    @Override
    public void mouseClicked(MouseEvent e) {
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new LabelCellRenderer(new JLabel()));
    }

    private void delete() {
        //get entry name
        int row = mTable.getSelectedRow();

        //send comment to server for the removal of user
        try {
            mConnection.delete(DestDef.DEST_ACL_ADMIN,
                               ScopeDef.SC_ACL_IMPLS,
                               ((JLabel)(mDataModel.getValueAt(row, 0))).getText());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            return;
        }

        //send comment to server and refetch the content
        refresh();
    }

    private void update() {
        //send request and parse data
        NameValuePairs response;
        try {
            response = mConnection.search(DestDef.DEST_ACL_ADMIN,
                               ScopeDef.SC_ACL_IMPLS,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            return;
        }

        Debug.println(response.toString());

        //parse the data
        int i=0;
        String[] vals = new String[response.size()];

        for (String entry : response.keySet()) {
            vals[i++] = entry.trim();
        }

        CMSAdminUtil.bubbleSort(vals);

        for (i=0; i<vals.length; i++) {
            String name = vals[i];
            Vector<Object> v = new Vector<>();
            v.addElement(new JLabel(name,
                    CMSAdminUtil.getImage(CMSAdminResources.IMAGE_ACLPLUGIN),
                    JLabel.LEFT));
            v.addElement(response.get(name));
            mDataModel.addRow(v);
        }

        if (mDataModel.getRowCount() >0)
            mTable.setRowSelectionInterval(0,0);
    }
}

