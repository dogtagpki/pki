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
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.tree.TreeNode;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.CMSResourceObject;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.ug.CMSUGTabPanel;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * CRL IP Panel
 *
 * @version $Revision$, $Date$
 */
public class CMSCRLIPPanel  extends CMSBaseTab
    implements MouseListener
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/

    private final static String PANEL_NAME = "CRLIPS";
    private final static String HELPINDEX = "configuration-revocation";

    private AdminConnection mAdmin;
    private CMSBaseResourceModel mModel;
    private CMSTabPanel mParent;
    private JList<JLabel> mList;
    private DefaultListModel<JLabel> mDataModel;
    private JScrollPane mScrollPane;
    private JButton mAdd;
    private JButton mEdit;
    private JButton mDelete;
    private Vector<String> mNames;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSCRLIPPanel(CMSBaseResourceModel model, CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mModel = model;
        mParent = parent;
        mDataModel = new DefaultListModel<>();
        mHelpToken = HELPINDEX;
        mNames = new Vector<>();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * initialize the UI components
     */
    public void init() {
        JPanel mainPanel = mCenterPanel;

        Debug.println("CRLIPPanel: init()");
        mAdmin = mModel.getServerInfo().getAdmin();

        GridBagLayout gb1 = new GridBagLayout();
        mainPanel.setLayout(gb1);

        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        JLabel listLabel = makeJLabel("CRLIPLIST");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,
                                DIFFERENT_COMPONENT_SPACE,
      		                    0,DIFFERENT_COMPONENT_SPACE);
        gb1.setConstraints(listLabel, gbc);
        mainPanel.add(listLabel);

        CMSAdminUtil.resetGBC(gbc);
        mList = makeJList(mDataModel, 7);
        mScrollPane = new JScrollPane(mList,
                                      JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                                      JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 0.5;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,
                                DIFFERENT_COMPONENT_SPACE,
      		                    0,DIFFERENT_COMPONENT_SPACE);
        gb1.setConstraints(mScrollPane, gbc);
        mainPanel.add(mScrollPane);

	    JPanel buttonPanel = createUserButtonPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,0,
      		                    0,DIFFERENT_COMPONENT_SPACE);
        gb1.setConstraints(buttonPanel, gbc);
        mainPanel.add(buttonPanel);

        refresh();
    }


    /**
     * create the user action button panel
     */
    protected JPanel createUserButtonPanel() {
        //add, edit, delete, help buttons required
        //actionlister to this object
        mAdd = makeJButton("ADD");
        mEdit = makeJButton("EDIT");
        mDelete = makeJButton("DELETE");
		JButton[] buttons = {mAdd, mEdit, mDelete};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    /**
     * refresh the panel data
     */
    public void refresh() {
        try {
            NameValuePairs nvps = mAdmin.search(DestDef.DEST_CA_ADMIN,
                                                ScopeDef.SC_CRLIPS,
                                                new NameValuePairs());
            populate(nvps);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
        }

        repaint(1);
    }


    /*==========================================================
	 * Event Handler
     *==========================================================*/

    //======= ActionLister ============================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mEdit)) {
            mModel.getFrame();
            String name = mList.getSelectedValue().getText();
						  //(String)mList.getSelectedValue();
            NameValuePairs nvps = new NameValuePairs();
            nvps.put(Constants.PR_ENABLED, "");
            nvps.put(Constants.PR_ID, "");
            nvps.put(Constants.PR_DESCRIPTION, "");
            nvps.put(Constants.PR_CLASS, "");
            try {
                NameValuePairs values = mAdmin.read(DestDef.DEST_CA_ADMIN,
                                                    ScopeDef.SC_CRLIPS,
                                                    name, nvps);

                CRLIPEditor editor = new CRLIPEditor(mAdmin, mModel.getFrame(),
                                             name, DestDef.DEST_CA_ADMIN,
                                             mModel.getServerInfo().getServerId(),
                                             mNames);
                editor.showDialog(values);
            } catch (EAdminException ex) {
                showErrorDialog(ex.toString());
            }
            refresh();
        } else if (e.getSource().equals(mAdd)) {
            CRLIPEditor editor = new CRLIPEditor(mAdmin, mModel.getFrame(),
                                         null, DestDef.DEST_CA_ADMIN,
                                         mModel.getServerInfo().getServerId(),
                                         mNames);
            editor.showDialog(new NameValuePairs());
            String name = editor.getCRLName();
            CMSResourceObject node = (CMSResourceObject)(mParent.getResourceObject());
            CMSResourceObject crlsNode = node;
            node = new CMSResourceObject();
            node.setName(name);
            CMSTabPanel crlIPTabPane = new CMSTabPanel(mModel, node);
            crlIPTabPane.addTab(new CMSCRLSettingPanel(crlIPTabPane, name));
            crlIPTabPane.addTab(new CMSCRLCachePanel(crlIPTabPane, name));
            crlIPTabPane.addTab(new CMSCRLFormatPanel(crlIPTabPane, name));
            node.setCustomPanel(crlIPTabPane);
            node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
            node.setAllowsChildren(true);
            crlsNode.insert(node, crlsNode.getChildCount());

            CMSResourceObject crlNode = node;

            node = new CMSResourceObject("CRLEXTENSIONS");
            CMSUGTabPanel crlExtTabPane1 = new CMSUGTabPanel(mModel, node);
            crlExtTabPane1.addTab(new CRLExtensionsInstanceTab(mModel, DestDef.DEST_CA_ADMIN, name));
            node.setCustomPanel(crlExtTabPane1);
            node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
            node.setAllowsChildren(false);
            crlNode.add(node);
            mModel.fireTreeStructureChanged(crlsNode);

            refresh();
        } else if (e.getSource().equals(mDelete)) {
            int index = mList.getSelectedIndex();
            if (index >= 0) {
                String name = mList.getSelectedValue().getText();
							  //(String)mList.getSelectedValue();

                int i = showConfirmDialog("DELETE");
                if (i == JOptionPane.YES_OPTION) {
                    try {
                        mAdmin.delete(DestDef.DEST_CA_ADMIN,
                                      ScopeDef.SC_CRLIPS, name);
                    } catch (EAdminException ex) {
                        showErrorDialog(ex.toString());
                    }
                    if (mNames.contains(name))
                        mNames.remove(name);
                    mDataModel.removeElementAt(index);
                    if (mDataModel.size() > 0)
                        mList.setSelectedIndex(0);
                }
                CMSResourceObject node =
                  (CMSResourceObject)(mParent.getResourceObject());
                Enumeration<TreeNode> allchildren = node.children();
                while (allchildren.hasMoreElements()) {
                    CMSResourceObject child = (CMSResourceObject)allchildren.nextElement();
                    String name1 = child.getName();
                    if (name1.equals(name)) {
                        node.remove(child);
                        mModel.fireTreeStructureChanged(node);
                        return;
                    }
                }
            }
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

        mDataModel.removeAllElements();
        mNames.removeAllElements();
        for (String name : nvps.keySet()) {
            if (name.indexOf('.') == -1) {
                mNames.addElement(name);

                String enable = nvps.get(name + "." + Constants.PR_ENABLED);
                if (enable != null && enable.equalsIgnoreCase(Constants.TRUE)) {
                    mDataModel.addElement(new JLabel(name,
                                          CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE),
                                          JLabel.LEFT));
                } else {
                    mDataModel.addElement(new JLabel(name,
                                          CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE_DISABLE),
                                          JLabel.LEFT));
                }
                /*
                mDataModel.addElement(name);
                */
            }
        }

        if (mDataModel.size() > 0) {
            mList.setSelectedIndex(0);
            mEdit.setEnabled(true);
            mDelete.setEnabled(true);
        } else {
            mEdit.setEnabled(false);
            mDelete.setEnabled(false);
        }
    }
}
