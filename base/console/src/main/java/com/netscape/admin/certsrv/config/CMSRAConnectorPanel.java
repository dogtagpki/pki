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
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

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
 * RA Connector Panel
 *
 * @author Christine Ho
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CMSRAConnectorPanel  extends CMSBaseTab
    implements MouseListener
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/

    private final static String PANEL_NAME = "CONNECTOR";
    private final static String HELPINDEX = "configuration-ra-connector-help";

    private AdminConnection mAdmin;
    private CMSBaseResourceModel mModel;
    private JList<String> mList;
    private DefaultListModel<String> mDataModel;
    private JScrollPane mScrollPane;
    private JButton mEdit;
    protected boolean mInit = false;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSRAConnectorPanel(CMSBaseResourceModel model, CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = model;
        mParent = parent;
        mDataModel = new DefaultListModel<>();
        mHelpToken = HELPINDEX;

        // hardcoded just for beta 1
        mDataModel.addElement("Certificate Manager Connector");
        mDataModel.addElement("Data Recovery Manager Connector");
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * initialize the UI components
     */
    @Override
    public void init() {
//        setLayout(new BorderLayout());

 //       JPanel mainPanel = new JPanel();
   JPanel mainPanel = mCenterPanel;


        Debug.println("ConnectorPanel: init()");
        mAdmin = mModel.getServerInfo().getAdmin();

        GridBagLayout gb1 = new GridBagLayout();
        mainPanel.setLayout(gb1);

        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        JLabel listLabel = makeJLabel("CONNLIST");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
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
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 0.5;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,
      		                            0,DIFFERENT_COMPONENT_SPACE);
        gb1.setConstraints(mScrollPane, gbc);
        mainPanel.add(mScrollPane);

        CMSAdminUtil.resetGBC(gbc);
        mEdit = makeJButton("EDIT");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
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
    @Override
    public void refresh() {
/*
        NameValuePairs response;
        mModel.progressStart();
        try {
            response = mAdmin.search(DestDef.DEST_RA_ADMIN,
              ScopeDef.SC_CONNECTOR, new NameValuePairs());

            Debug.println(response.toString());
            populate(response);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
        }
        mModel.progressStop();
*/
    }

    /*==========================================================
	 * Event Handler
     *==========================================================*/

    //======= ActionLister ============================
    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mEdit)) {
            mModel.getFrame();
            String name = mList.getSelectedValue();
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
                NameValuePairs values = mAdmin.read(DestDef.DEST_RA_ADMIN,
                  ScopeDef.SC_CONNECTOR, name, nvps);

                mAdmin.search(DestDef.DEST_SERVER_ADMIN,
                  ScopeDef.SC_SUBSYSTEM, new NameValuePairs());

                boolean colocated = false;
                if (name.equals("Data Recovery Manager Connector")) {
                    String val = values.get("id");
                    if (val != null && val.equals("kra"))
                        colocated = true;
                }
                ConnectorEditor editor = new ConnectorEditor(mAdmin,
                  mModel.getFrame(), name, DestDef.DEST_RA_ADMIN,
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
    @Override
    public void mouseClicked(MouseEvent e) {
        if (e.getSource() == mList) {
            if (mList.getSelectedIndex() < 0)
                mEdit.setEnabled(false);
            else
                mEdit.setEnabled(true);
        }
    }

    @Override
    public void mousePressed(MouseEvent e) {}
    @Override
    public void mouseReleased(MouseEvent e) {}
    @Override
    public void mouseEntered(MouseEvent e) {}
    @Override
    public void mouseExited(MouseEvent e) {}

    //======== CMSBaseConfigPanel ==============
    @Override
    public boolean applyCallback() {
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
}
