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
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * CA Connector Panel
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSCAConnectorPanel  extends CMSBaseTab
    implements MouseListener
{

    /*==========================================================
     * variables
     *==========================================================*/

    private final static String PANEL_NAME = "CACONNECTOR";
    private final static String HELPINDEX = "configuration-ca-connector-help";

    private AdminConnection mAdmin;
    private CMSBaseResourceModel mModel;
    private CMSTabPanel mParent;
    private JList mList;
    private DefaultListModel mDataModel;
    private JScrollPane mScrollPane;
    private JButton mEdit;
    protected boolean mInit = false;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSCAConnectorPanel(CMSBaseResourceModel model, CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = model;
        mParent = parent;
        mDataModel = new DefaultListModel();
        mHelpToken = HELPINDEX;

        // hardcoded just for beta 1
        mDataModel.addElement("Data Recovery Manager Connector");
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * initialize the UI components
     */
    public void init() {
//        setLayout(new BorderLayout());

  //      JPanel mainPanel = new JPanel();
        JPanel mainPanel = mCenterPanel;


        Debug.println("ConnectorPanel: init()");
        mAdmin = mModel.getServerInfo().getAdmin();

        GridBagLayout gb1 = new GridBagLayout();
        mainPanel.setLayout(gb1);

        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        JLabel listLabel = makeJLabel("CONNLIST");
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        gb1.setConstraints(listLabel, gbc);
        mainPanel.add(listLabel);

        CMSAdminUtil.resetGBC(gbc);
        mList = makeJList(mDataModel, 3);
        mScrollPane = new JScrollPane(mList,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 0.5;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        gb1.setConstraints(mScrollPane, gbc);
        mainPanel.add(mScrollPane);

        CMSAdminUtil.resetGBC(gbc);
        mEdit = makeJButton("EDIT");
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(COMPONENT_SPACE,0,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        gb1.setConstraints(mEdit, gbc);
        mainPanel.add(mEdit);

 //       add("Center",mainPanel);
        refresh();
    }

    /**
     * refresh the panel data
     */
    public void refresh() {
	repaint(1);
    }

    /*==========================================================
	 * Event Handler
     *==========================================================*/

    //======= ActionLister ============================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mEdit)) {
            JFrame frame = mModel.getFrame();
            String name = (String)mList.getSelectedValue();
            NameValuePairs nvps = new NameValuePairs();
            nvps.put(Constants.PR_ID, "");
            nvps.put(Constants.PR_HOST, "");
            nvps.put(Constants.PR_PORT, "");
            // Inserted by beomsuk
            nvps.put(Constants.PR_TIMEOUT, "");
            // Insert end
            nvps.put(Constants.PR_URI, "");
            nvps.put(Constants.PR_LOCAL, "");
            nvps.put(Constants.PR_ENABLE, "");

            try {
                NameValuePairs values = mAdmin.read(DestDef.DEST_CA_ADMIN,
                  ScopeDef.SC_CONNECTOR, name, nvps);
                NameValuePairs subsystems = mAdmin.search(DestDef.DEST_SERVER_ADMIN,
                  ScopeDef.SC_SUBSYSTEM, new NameValuePairs());
 
                boolean colocated = false;
                if (name.equals("Data Recovery Manager Connector")) {
                    String val = values.get("id");
                    if (val != null && val.equals("kra"))
                        colocated = true;
                }

                ConnectorEditor editor = new ConnectorEditor(mAdmin,
                  mModel.getFrame(), name, DestDef.DEST_CA_ADMIN, 
                  mModel.getServerInfo().getServerId(), colocated);
                editor.showDialog(values);
            } catch (EAdminException ex) {
                showErrorDialog(ex.toString());
            }
/*
                NameValuePairs values = new NameValuePairs();
                ConnectorEditor editor = new ConnectorEditor(mAdmin,
                  mModel.getFrame(), name);
                editor.showDialog(values);
*/
        }
    }

    //=== MOUSELISTENER ========================
    public void mouseClicked(MouseEvent e) {
        if (e.getSource() == mList) {
            if (mList.getSelectedIndex() < 0)
                mEdit.setEnabled(false);
            else
                mEdit.setEnabled(true);
        }
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {}

    //======== CMSBaseConfigPanel ==============
    public boolean applyCallback() {
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

    /*==========================================================
	 * private methods
     *==========================================================*/

    //update the UI component using the data retrieved
    private void populate(NameValuePairs nvps) {
/*
        Enumeration names = nvps.getNames();
        mDataModel.removeAllElements();
        while (names.hasMoreElements())
            mDataModel.addElement(names.nextElement());

        if (mDataModel.size() > 0) {
            mList.setSelectedIndex(0);
            mEdit.setEnabled(true);
        } else
            mEdit.setEnabled(false);
*/
    }
}
