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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ResourceBundle;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Policy Rule Order Dialog - <p>
 *
 * The administrator can use this dialog to reconfig the ordering
 * of the existing policy rules.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class PolicyRuleOrderDialog extends JDialog
    implements ActionListener, MouseListener
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "POLICYORDERDIALOG";

    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private ResourceBundle mResource;
    protected DefaultListModel<JLabel> mDataModel;
    protected String mDestination;              //dest flag

    private JScrollPane mScrollPane;
    private JList<JLabel> mList;

    private JButton mOK, mCancel, mUp, mDown, mHelp;
    private final static String RAHELPINDEX =
      "configuration-ra-reorder-policyrule-dbox-help";
    private final static String KRAHELPINDEX =
      "configuration-kra-reorder-policyrule-dbox-help";
    private final static String CAHELPINDEX =
      "configuration-ca-reorder-policyrule-dbox-help";
    private String mHelpToken;

    /*==========================================================
     * constructors
     *==========================================================*/
    public PolicyRuleOrderDialog(JFrame parent, AdminConnection conn, String dest) {
        super(parent,true);
        mParentFrame = parent;
        mConnection = conn;
        mDestination = dest;
        if (mDestination.equals(DestDef.DEST_RA_POLICY_ADMIN))
            mHelpToken = RAHELPINDEX;
        else if (mDestination.equals(DestDef.DEST_KRA_POLICY_ADMIN))
            mHelpToken = KRAHELPINDEX;
        else
            mHelpToken = CAHELPINDEX;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new DefaultListModel<>();
        setSize(360, 216);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * show the windows
     * @param users list of current groups
     */
    public void showDialog(Vector<String> rules) {

        mDataModel.clear();
        for (int i=0; i<rules.size(); i++)
            mDataModel.addElement(
                new JLabel(rules.elementAt(i),
                CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULE),
                JLabel.LEFT));
        if (mDataModel.getSize() >0)
            mList.setSelectedIndex(0);

        refresh();
        setArrowButtons();
        this.setVisible(true);
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	@Override
    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {
            try {
                saveOrder();
            } catch (EAdminException e) {
                //display error dialog
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            this.dispose();
        }
        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }
        if (evt.getSource().equals(mUp)) {
            int index = mList.getSelectedIndex();
            JLabel obj = mDataModel.elementAt(index);
            mDataModel.removeElementAt(index);
            mDataModel.insertElementAt(obj,index-1);
            mList.setSelectedIndex(index-1);
            setArrowButtons();
            refresh();
        }
        if (evt.getSource().equals(mDown)) {
            int index = mList.getSelectedIndex();
            JLabel obj = mDataModel.elementAt(index);
            mDataModel.removeElementAt(index);
            mDataModel.insertElementAt(obj,index+1);
            mList.setSelectedIndex(index+1);
            setArrowButtons();
            refresh();
        }
        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
    }

    //==== MOUSELISTENER ======================
    @Override
    public void mouseClicked(MouseEvent e) {
        setArrowButtons();
    }

    @Override
    public void mousePressed(MouseEvent e) {}
    @Override
    public void mouseReleased(MouseEvent e) {
        setArrowButtons();
    }
    @Override
    public void mouseEntered(MouseEvent e) {}
    @Override
    public void mouseExited(MouseEvent e) {
        setArrowButtons();
    }

    /*==========================================================
	 * private methods
     *==========================================================*/
    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
		GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.weightx = 1.0;
		gbc.weighty = 1.0;
                gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(content, gbc);
		center.add(content);

		//action panel
		JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridheight = GridBagConstraints.REMAINDER;
		gbc.weightx = 1.0;
        gb.setConstraints(action, gbc);
		center.add(action);

		getContentPane().add("Center",center);
    }

    /**
     * create the bottom action button panel
     */
    protected JPanel createUDButtonPanel() {
        //up, down buttons required
        //actionlister to this object
        mUp = CMSAdminUtil.makeJButton(mResource, PREFIX, "UP", null, this);
        mDown = CMSAdminUtil.makeJButton(mResource, PREFIX, "DOWN", null, this);
		JButton[] buttons = { mUp, mDown};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
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

    private JPanel makeContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        //left side certificate table
        mList = CMSAdminUtil.makeJList(mDataModel,10);
		mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		mList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
		mList.addMouseListener(this);
		mScrollPane.setBackground(Color.white);
		mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());

		CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,CMSAdminUtil.COMPONENT_SPACE,0,0);
        gb.setConstraints(mScrollPane, gbc);
		mListPanel.add(mScrollPane);

	    JPanel buttonPanel = createUDButtonPanel();
		CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,0,0,0);
        gb.setConstraints(buttonPanel, gbc);
		mListPanel.add(buttonPanel);

        return mListPanel;
    }

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //save order information to the server
    private void saveOrder() throws EAdminException {
        StringBuffer buf = new StringBuffer();

        int x = 0;
        for(int i=0; i<mDataModel.size(); i++) {
            if (x > 0)
                buf.append(",");
            x++;
            buf.append(mDataModel.getElementAt(i).getText());
        }

        NameValuePairs nvp = new NameValuePairs();
        nvp.put(Constants.PR_POLICY_ORDER, buf.toString());

        Debug.println("ORDER: "+buf.toString());

        mConnection.modify(mDestination,
                               ScopeDef.SC_POLICY_RULES,
                               Constants.RS_ID_ORDER,
                               nvp);
    }

    //set arrow buttons
    private void setArrowButtons() {

        //enable and diable buttons accordingly
        Debug.println("setArrowButtons() - "+mList.getSelectedIndex());
        if (mList.getSelectedIndex()< 0) {
            mUp.setEnabled(false);
            mDown.setEnabled(false);
            mOK.setEnabled(false);
            return;
        }

        if (mList.getSelectedIndex()==0)
            mUp.setEnabled(false);
        else
            mUp.setEnabled(true);
        if (mList.getSelectedIndex()< mDataModel.getSize()-1)
            mDown.setEnabled(true);
        else
            mDown.setEnabled(false);
        mOK.setEnabled(true);
    }

    //refresh the table content
    private void refresh() {
        //mTable.invalidate();
        //mTable.validate();
        //mTable.repaint(1);
		mScrollPane.invalidate();
		mScrollPane.validate();
		//mScrollPane.repaint(1);
		repaint();
    }

}
