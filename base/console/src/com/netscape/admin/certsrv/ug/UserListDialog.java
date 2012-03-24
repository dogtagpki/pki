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
package com.netscape.admin.certsrv.ug;

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * User Listing Dialog - <p>
 *
 * This dialog support multiple user selection and displays
 * only users that are not in the current group. This dialog
 * will be created once and being reused per group editor.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class UserListDialog extends JDialog
    implements ActionListener, MouseListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "USERLISTDIALOG";

    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private ResourceBundle mResource;
    protected DefaultListModel mDataModel;
    protected Vector mCurrentUsers;
    protected Vector mSelectedUser;

    private JScrollPane mScrollPane;
    private JList mList;

    private JButton mOK, mCancel;
    private boolean mIsOk = false;

    /*==========================================================
     * constructors
     *==========================================================*/
    public UserListDialog(JFrame parent, AdminConnection conn) {
        super(parent,true);
        mParentFrame = parent;
        mConnection = conn;
        mSelectedUser = new Vector();
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new DefaultListModel();
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
     * @param users list of current users
     */
    public void showDialog(Vector users) {

        mCurrentUsers = users;
        mSelectedUser.removeAllElements();

        //retrieve the cert record from the server
        try {
            refresh();
        } catch (EAdminException ex) {
            CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                    "SERVERERROR", CMSAdminUtil.ERROR_MESSAGE);
            return;
        }
        setButtons();
        mIsOk = false;
        this.show();
    }


    /**
     * if selection is ok, the user name will be returned
     * otherwise, empty string will be returned.
     * @return user name
     */
    public Vector getSelectedUser() {
        return mSelectedUser;
    }

    /**
     * get the exit code
     * @return true if ok; otherwise false
     */
    public boolean isOK() {
        return mIsOk;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mOK)) {
            //get selected user
            int[] rowIndex = mList.getSelectedIndices();
            //Debug.println("Rows Selected ="+rowIndex.length);
            for (int j=0; j< rowIndex.length; j++)
                mSelectedUser.addElement(
                    ((JLabel)mDataModel.elementAt(rowIndex[j])).getText());

            //set return flag
            mIsOk = true;
            this.hide();
        }

        if (evt.getSource().equals(mCancel)) {
            this.hide();
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}

    public void mouseEntered(MouseEvent e) {
        setButtons();
    }
    public void mouseExited(MouseEvent e) {
        setButtons();
    }

    /*==========================================================
	 * private methods
     *==========================================================*/

    //set buttons
    private void setButtons() {
        if (mList.getSelectedIndex()< 0) {
            mOK.setEnabled(false);
            return;
        }
        mOK.setEnabled(true);
    }

    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
		GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = gbc.NORTH;
		gbc.gridwidth = gbc.REMAINDER;
                gbc.fill = gbc.BOTH;
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
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
		JButton[] buttons = { mOK, mCancel};
		JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons );
    }

    private JPanel makeContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

        mList = CMSAdminUtil.makeJList(mDataModel,9);
        mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        return mListPanel;

        /*
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout(gb3);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        //left side certificate table
        mTable = new JTable(mDataModel);
		mScrollPane = JTable.createScrollPaneForTable(mTable);
		//mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PREFIX,"CERTIFICATE"));
		mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		int width = CMSAdminUtil.getTotalColumnWidth( mTable );
		//Dimension d = new Dimension( width, mTable.getRowHeight()*14);
		//mTable.setMinimumSize( d );
		//mTable.setSize( d );
		mTable.setAutoscrolls(true);
		mTable.sizeColumnsToFit(true);
		mTable.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		//mTable.getSelectionModel().addListSelectionListener(new StandardListSelectionListener());
		//mTable.addMouseListener(this);
		//mTable.setPreferredScrollableViewportSize(d);
		setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        gb3.setConstraints(mScrollPane, gbc);
		content.add(mScrollPane);

        return content;
        */
    }

	/*Set the first column's cellrender as label cell
	protected void setLabelCellRenderer(JTable table, int index) {
	    table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
	}
	*/

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //retrieve group information from the server
    private void refresh() throws EAdminException {
        mDataModel.removeAllElements();

        NameValuePairs response;
        try {
            response = mConnection.search(DestDef.DEST_USER_ADMIN,
                               ScopeDef.SC_USERS,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }

        //parse the data
/*
        Vector store = new Vector();
        for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            if (mCurrentUsers.indexOf(entry)== -1)
            store.addElement(entry);
        }

        String[] vals = new String[store.size()];
        store.copyInto(vals);
*/

       String responseValue = response.get("userInfo");

       StringTokenizer tokenizer = new StringTokenizer(responseValue, ";");
       StringTokenizer subTokenizer = null;

       Vector store = new Vector();
       Hashtable table = new Hashtable();

       while (tokenizer.hasMoreTokens()) {
           String t = (String)tokenizer.nextToken();
           subTokenizer = new StringTokenizer(t, ":");
           int i=0;
           String str1 = null;
           String str2 = null;
           while (subTokenizer.hasMoreTokens()) {
               if (i == 0) {
                   str1 = (String)subTokenizer.nextToken();
                   store.addElement(str1);
               } else {
                   str2 = (String)subTokenizer.nextToken();
                   table.put(str1, str2);
               }
               i++;
           }
       }

       String[] vals = new String[store.size()];
       store.copyInto(vals);

        CMSAdminUtil.bubbleSort(vals);

        for (int y=0; y< vals.length ; y++) {
            mDataModel.addElement(new JLabel(vals[y],
                CMSAdminUtil.getImage(CMSAdminResources.IMAGE_USER),
                JLabel.LEFT));
        }

        refreshTable();
    }

    //refresh the table content
    private void refreshTable() {
        //mTable.invalidate();
        //mTable.validate();
        //mTable.repaint(1);
		//mScrollPane.invalidate();
		//mScrollPane.validate();
		//mScrollPane.repaint(1);
		//repaint();
    }

}
