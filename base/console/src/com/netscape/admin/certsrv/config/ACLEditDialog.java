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
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * ACL Editor
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ACLEditDialog extends JDialog
    implements ActionListener, MouseListener
{
    private final static String PREFIX = "ACLEDITDIALOG";
    private final static String HELPINDEX =
      "configuration-authorization";
    private JScrollPane mScrollPane;
    private JList mList;
    private JFrame mParentFrame;
    private JButton mOK, mCancel, mHelp;
    private JButton mAdd, mEdit, mDelete;
    private ResourceBundle mResource;
    private String mResourceName, mDesc;
    private DefaultListModel mDataModel;
    private String mOperations;
    private AdminConnection mAdmin;
    private ACIDialog mDialog;
    private String mHelpToken;
    private JTextArea mDescArea, mHelpArea;
    private JTextField mResourceText, mRightsText;
    private boolean mIsNew = false;
    private Color mActiveColor;

    public ACLEditDialog(AdminConnection admin, JFrame parent) {
        this(admin, parent, null, null);
    }

    public ACLEditDialog(AdminConnection admin, JFrame parent, 
      String name, String desc) {
        super(parent,true);
        mParentFrame = parent;
        mResource = ResourceBundle.getBundle(
          CMSAdminResources.class.getName());
        mDesc = desc;
        mResourceName = name;
        if (mResourceName == null)
            mIsNew = true;
        mAdmin = admin;
        mHelpToken = HELPINDEX;
        mDataModel = new DefaultListModel();
        setSize(460, 420);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mCancel)) {
            if (mDialog != null) {
                mDialog.dispose();
                mDialog = null;
            }
            this.dispose();
        } else if (evt.getSource().equals(mDelete)) {
            int index = mList.getSelectedIndex();
            if (index >= 0) {
                int i = CMSAdminUtil.showConfirmDialog(mParentFrame, 
                  mResource, PREFIX, "DELETE", CMSAdminUtil.WARNING_MESSAGE);
                if (i == JOptionPane.YES_OPTION) {
                    mDataModel.removeElementAt(index);
                    Debug.println("Deleted");
                    if (mDataModel.size() > 0) 
                        mList.setSelectedIndex(0);
                }
            }
        } else if (evt.getSource().equals(mOK)) {
            if (mIsNew) {
                mResourceName = mResourceText.getText().trim();
                if (mResourceName.equals("")) {
                    String msg = mResource.getString(
                      PREFIX+"_DIALOG_EMPTYRESOURCEID_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mParentFrame, 
                      mResource, msg, CMSAdminUtil.ERROR_MESSAGE); 
                    return;
                }
            }
     
            String rights = mRightsText.getText().trim();

            NameValuePairs pairs = new NameValuePairs();
            if (!rights.equals("")) {
                String str = "";
                int size=mDataModel.getSize();
                if (size == 0) {
                    String msg = mResource.getString(
                      PREFIX+"_DIALOG_EMPTYACIS_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mParentFrame,
                      mResource, msg, CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }

                String desc = mDescArea.getText().trim();
                if (desc.equals("")) {
                    String msg = mResource.getString(
                      PREFIX+"_DIALOG_EMPTYDESC_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mParentFrame,
                      mResource, msg, CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }

                for (int i=0; i<size; i++) {
                    if (i > 0)
                        str = str+";"+(String)mDataModel.elementAt(i);
                    else
                        str = str+(String)mDataModel.elementAt(i);
                }
                pairs.put(Constants.PR_ACI, str);
                pairs.put(Constants.PR_ACL_DESC, desc);
                pairs.put(Constants.PR_ACL_RIGHTS, rights);
            }

            try {
                mAdmin.modify(DestDef.DEST_ACL_ADMIN, ScopeDef.SC_ACL,
                  mResourceName, pairs);
                if (mDialog != null) {
                    mDialog.dispose();
                    mDialog = null;
                }
                this.dispose();
            } catch (EAdminException e) {
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource, e.getMessage(),
                  CMSAdminUtil.ERROR_MESSAGE);
            }
        } else if (evt.getSource().equals(mAdd)) {
            String rights = mRightsText.getText().trim();
            if (rights.equals("")) { 
                String msg = mResource.getString(
                  PREFIX+"_DIALOG_EMPTYRIGHTS_MESSAGE");
                CMSAdminUtil.showErrorDialog(mParentFrame, 
                  mResource, msg, CMSAdminUtil.ERROR_MESSAGE); 
                  return;
            }
            mOperations = rights;
            mDialog = new ACIDialog(mParentFrame, mOperations, mAdmin);
            mDialog.showDialog("", true);
            if (mDialog.getOK()) {
                mDataModel.addElement(mDialog.getValue());
                mList.setSelectedIndex(mDataModel.size()-1);
                mDelete.setEnabled(true);
                mEdit.setEnabled(true);
            }
            mDialog = null;
        } else if (evt.getSource().equals(mEdit)) {
            mDialog = new ACIDialog(mParentFrame, mOperations, mAdmin);
            int index = mList.getSelectedIndex();
            if (index >= 0) {
                String aci = (String)mDataModel.elementAt(index);
                mDialog.showDialog(aci, false);

                if (mDialog.getOK())
                    mDataModel.setElementAt(mDialog.getValue(), index);
            }
            mDialog = null;
        } else if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
    }

    public void showDialog() {
        mEdit.setEnabled(false);
        mDelete.setEnabled(false);
        this.show();
    }

    public void showDialog(NameValuePairs data) {
        String aci = data.get(Constants.PR_ACI);
        mOperations = data.get(Constants.PR_ACL_OPS);

        if ((aci != null) && (!aci.trim().equals(""))) {
            StringTokenizer tokenizer = new StringTokenizer(aci, ";");
            while (tokenizer.hasMoreElements())
                mDataModel.addElement(tokenizer.nextElement());
        }
        if (mList.getSelectedIndex() < 0) {
            mEdit.setEnabled(false);
            mDelete.setEnabled(false);
        } else {
            mEdit.setEnabled(true);
            mDelete.setEnabled(true);
        }

        if (!mIsNew)
            mRightsText.setText(mOperations);

        this.show();
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
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(content, gbc);
        center.add(content);

        // Help Panel
        JPanel helpPanel = makeHelpPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        gbc.insets = new Insets(CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(helpPanel, gbc);
        center.add(helpPanel);
        
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

    public void mouseClicked(MouseEvent e) {
        if (e.getSource() == mList) {
            if (mList.getSelectedIndex() < 0) {
                mDelete.setEnabled(false);
                mEdit.setEnabled(false);
            } else {
                mDelete.setEnabled(true);
                mEdit.setEnabled(true);
            }
           
            return;
        }

        Component comp = (Component)e.getSource();
        String str = comp.getName();
        String text = "";
        if (str.equals("resourceID")) {
            text = mResource.getString(PREFIX+"_RESOURCEID_HELP");
        } else if (str.equals("rights")) {
            text = mResource.getString(PREFIX+"_RIGHTS_HELP");
        } else if (str.equals("aci")) {
            text = mResource.getString(PREFIX+"_ACI_HELP");
        } else if (str.equals("description")) {
            text = mResource.getString(PREFIX+"_DESC_HELP");
        }
        mHelpArea.setText(text);
    }

    public void mousePressed(MouseEvent e) {
    }
    public void mouseReleased(MouseEvent e) {
    }
    public void mouseEntered(MouseEvent e) {
    }
    public void mouseExited(MouseEvent e) {
    }

    /**
     * create the bottom action button panel
     */
    private JPanel createUDButtonPanel() {
        //up, down buttons required
        //actionlister to this object
        mAdd = CMSAdminUtil.makeJButton(mResource, PREFIX, "ADD", null, this);
        mDelete = CMSAdminUtil.makeJButton(mResource, PREFIX, "DELETE", 
          null, this);
        mEdit = CMSAdminUtil.makeJButton(mResource, PREFIX, "EDIT", null, this);
        JButton[] buttons = {mAdd, mDelete, mEdit};
        JButtonFactory.resize(buttons);
        return CMSAdminUtil.makeJButtonVPanel(buttons);
    }

    //create botton action panel
    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
        //JButton[] buttons = { mOK, mCancel, mHelp};
        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    private JPanel makeHelpPanel() {
        JPanel helpPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        helpPanel.setBorder(CMSAdminUtil.makeEtchedBorder());
        helpPanel.setLayout(gb);

        mHelpArea = new JTextArea();
        mHelpArea.setRows(20);
        mHelpArea.setLineWrap(true);
        mHelpArea.setWrapStyleWord(true);
        mHelpArea.setBackground(helpPanel.getBackground());
        mHelpArea.setEditable(false);
        
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.fill=gbc.BOTH;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
/*
        gbc.insets = new Insets(0,
                CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
*/
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
    //    gbc.gridx = 1;
    //    gbc.gridy = 1;
        gb.setConstraints(mHelpArea, gbc);
        helpPanel.add(mHelpArea);
        mHelpArea.setText(mResource.getString(PREFIX+"_INTRO_HELP"));
        return helpPanel;
    }

    private JPanel makeContentPanel() {
        JPanel mainPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mainPanel.setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "RESOURCEOBJECT", null);
        gbc.anchor = gbc.WEST;
	gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
				CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
				0, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(label1, gbc);
        mainPanel.add(label1);
        label1.setName("resourceID");
        label1.addMouseListener(this);

        CMSAdminUtil.resetGBC(gbc);
        if (mIsNew) {
            mResourceText = new JTextField(30);
            gbc.anchor = gbc.WEST;
            gbc.gridwidth = gbc.REMAINDER;
            gb.setConstraints(mResourceText, gbc);
            mainPanel.add(mResourceText);
        } else {
            JLabel label2 = new JLabel(mResourceName);
            gbc.anchor = gbc.WEST;
            gbc.gridwidth = gbc.REMAINDER;
            gb.setConstraints(label2, gbc);
            mainPanel.add(label2);
        }

        CMSAdminUtil.resetGBC(gbc);
        JLabel rightsLbl = CMSAdminUtil.makeJLabel(
          mResource, PREFIX, "RIGHTS", null);
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
			CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
			0, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(rightsLbl, gbc);
        mainPanel.add(rightsLbl);
        rightsLbl.setName("rights");
        rightsLbl.addMouseListener(this);
   
        CMSAdminUtil.resetGBC(gbc);
        mRightsText = new JTextField(30);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(mRightsText, gbc);
        mainPanel.add(mRightsText);

        JLabel aciLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "ACI", null);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
				CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
				0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(aciLbl, gbc);
        mainPanel.add(aciLbl);
        aciLbl.setName("aci");
        aciLbl.addMouseListener(this);

        JPanel listPanel = makeListPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
	gbc.weightx = 1.0;
	gbc.weighty = 1.0;
        gbc.fill=gbc.BOTH;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0,
				CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
				0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(listPanel, gbc);
        mainPanel.add(listPanel);

        JLabel descLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "DESC", null);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
				CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
				0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(descLbl, gbc);
        mainPanel.add(descLbl);
        descLbl.setName("description");
        descLbl.addMouseListener(this);

        CMSAdminUtil.resetGBC(gbc);
        mDescArea = new JTextArea();
        mDescArea.setRows(20);
        mDescArea.setLineWrap(true);
        mDescArea.setWrapStyleWord(true);
        if (mDesc != null)
            mDescArea.setText(mDesc);
        JScrollPane scrollPane = createScrollPane(mDescArea);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.fill=gbc.BOTH;
        gbc.insets = new Insets(0,
				CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
				0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
    //    gbc.gridx = 1;
    //    gbc.gridy = 1;
        gb.setConstraints(scrollPane, gbc);
        mainPanel.add(scrollPane);

/*
        mActiveColor = mDescArea.getBackground();

        if (mIsNew)
            enableTextField(mResourceText, true, mActiveColor);
        else
            enableTextField(mResourceText, false, getBackground());
*/
        return mainPanel;
    }

    private void enableTextField(JTextField textFld, boolean enabled, 
      Color color) {
        textFld.setEnabled(enabled);
        textFld.setEditable(enabled);
        textFld.setBackground(color);
        CMSAdminUtil.repaintComp(textFld);
    }

    private JScrollPane createScrollPane(JComponent component) {

        JScrollPane scrollPane = new JScrollPane(component,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setBackground(getBackground());
        scrollPane.setAlignmentX(LEFT_ALIGNMENT);
        scrollPane.setAlignmentY(TOP_ALIGNMENT);
        scrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        return scrollPane;
    }

    private JPanel makeListPanel() {
        JPanel listPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        listPanel.setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        mList = CMSAdminUtil.makeJList(mDataModel,9);
        mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        mList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        //gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        listPanel.add(mScrollPane);

        CMSAdminUtil.resetGBC(gbc);
        JPanel VBtnPanel = createUDButtonPanel();
        gbc.anchor = gbc.NORTHWEST;
	gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(VBtnPanel, gbc);
        listPanel.add(VBtnPanel);

        return listPanel;
    }
}
