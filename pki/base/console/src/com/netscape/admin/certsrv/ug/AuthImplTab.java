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
import com.netscape.admin.certsrv.config.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Auth Plugin Management Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class AuthImplTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String IMPL_NAME = AuthImplDataModel.IMPL_NAME;
    private static final String IMPL_CLASS = AuthImplDataModel.IMPL_CLASS;
    private static final String IMPL_DESC = AuthImplDataModel.IMPL_DESC;
    private static final String IMPL_TYPE = AuthImplDataModel.IMPL_TYPE;

    private static final String PANEL_NAME = "AUTHIMPL";
    private static final String TOKEN = ";";

    private AdminConnection mConnection;
    private String mDestination;

    protected JScrollPane mScrollPane;
    protected JTable mTable;                    //table
    protected AuthImplDataModel mDataModel;     //table model
    protected AuthRegisterDialog mEditor=null;  //keep single copy
    protected JButton mRefresh, mAdd, mDelete, mHelp;
    private static final String HELPINDEX = 
      "authentication-certsrv-authplugin-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public AuthImplTab(CMSBaseResourceModel model) {
        super(PANEL_NAME, model);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new AuthImplDataModel();
        mDestination = DestDef.DEST_AUTH_ADMIN;
        mHelpToken = HELPINDEX;
    }

    /*==========================================================
     * public methods
     *==========================================================*/


    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            refresh();
        }
        if (e.getSource().equals(mAdd)) {
            if (mEditor==null)
                mEditor = new AuthRegisterDialog(mModel.getFrame(), mConnection);
            mEditor.showDialog(mDestination, ScopeDef.SC_AUTH_IMPLS);

            if (mEditor.isOK())
                refresh();
        }
        if (e.getSource().equals(mDelete)) {
            Debug.println("Delete");
            if(mTable.getSelectedRow()< 0)
                return;
            int i = showConfirmDialog("DELETE");
            if (i == JOptionPane.YES_OPTION) {
                delete();
                Debug.println("Deleted");
            }
        }
        if (e.getSource().equals(mHelp)) {
            helpCallback();
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();
    }
    
    public void mouseReleased(MouseEvent e) {
        setButtons();    
    }

    /*==========================================================
     * protected methods
     *==========================================================*/
    public void refresh() {

        mDataModel.removeAllRows();
        update();

        setButtons();
        mTable.invalidate();
        mTable.validate();
        mScrollPane.invalidate();
        mScrollPane.validate();
        mScrollPane.repaint(1);
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

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        JButton[] buttons = { mRefresh, mHelp };
        return makeJButtonPanel(buttons, true);
    }

    protected JPanel createListPanel() {
        mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

        //center table
        mTable = new JTable(mDataModel);
        mScrollPane = JTable.createScrollPaneForTable(mTable);
        //mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PANEL_NAME,"USERS"));
        mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mTable.addMouseListener(this);
        setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
      gbc.fill = gbc.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        JPanel buttonPanel = createButtonPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(buttonPanel, gbc);
        mListPanel.add(buttonPanel);

        refresh();

        return mListPanel;
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    //set buttons
    private void setButtons() {

        //enable and diable buttons accordingly
        //Debug.println("setButtons() - "+mTable.getSelectedRow());
        //Debug.println("setButtons() - "+mTable.getSelectionModel().isSelectionEmpty());
        if (mTable.getSelectionModel().isSelectionEmpty()) {
            mDelete.setEnabled(false);
            return;
        }

        if(mDataModel.getRowCount()< 0) {
            mDelete.setEnabled(false);
            return;
        }

        mDelete.setEnabled(true);
        int index = mTable.getSelectedRow();

        if (index >= 0) {
            NameValuePairs nvp =
              (NameValuePairs)mDataModel.getObjectValueAt(index);
            String type = nvp.getValue(IMPL_TYPE);
            if (type.equals(Constants.VIEW) || type.equals(Constants.VIEW))
                mDelete.setEnabled(false);
        }
    }

    //=============================================
    // SEND REQUESTS TO THE SERVER SIDE
    //=============================================
    private void update() {
        //send request and parse data

        mModel.progressStart();
        NameValuePairs response;
        try {
            response = mConnection.search(mDestination,
                               ScopeDef.SC_AUTH_IMPLS,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        Debug.println(response.toString());

        //parse the response
		//The response is a set of name
        int i=0;
        String[] vals = new String[response.size()];
        Hashtable data = new Hashtable();
        for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            String value = response.getValue(entry);
			Debug.println("AuthImplTab.java update(): "+
						"entry="+entry+
						"value="+value
				);
            int x = value.indexOf(",");
            int y = value.indexOf(TOKEN);
            NameValuePairs obj = new NameValuePairs();
            obj.add(IMPL_NAME,entry);
			Debug.println("x="+x);
            if(x != -1) {
				Debug.println("0 obj.add(IMPL_CLASS,"+value.substring(0,x));
                obj.add(IMPL_CLASS, value.substring(0,x));
                if (y == -1) {
					Debug.println("1 obj.add(IMPL_DESC,"+value.substring(0,x));
                    obj.add(IMPL_DESC, value.substring(x+1));
				}
                else {
					Debug.println("1 obj.add(IMPL_DESC,"+value.substring(x+1,y));
                    obj.add(IMPL_DESC, value.substring(x+1, y));
				}
            } else {
				Debug.println(" 2 obj.add(IMPL_CLASS,"+value.substring(0,y));
                obj.add(IMPL_CLASS, value.substring(0,y));
				Debug.println(" 2 obj.add(IMPL_DESC,\"\"");
                obj.add(IMPL_DESC,"");
            }

            String type = "";
			Debug.println("y="+y);
            if (y == -1) {
                type = Constants.EDIT;
                obj.add(IMPL_TYPE, Constants.EDIT);
            } else {
                type = value.substring(y+1);
                obj.add(IMPL_TYPE, type);
            }
            if (type.equals(Constants.EDIT)) {
                data.put(entry,obj);
                vals[i++]= entry ;
            }
        }

        if (i >= 1) {
            String[] valCopy = new String[i];
            System.arraycopy(vals, 0, valCopy, 0, i);
            CMSAdminUtil.bubbleSort(valCopy);
            for (int y=0; y< valCopy.length ; y++) {
				if (data.get(valCopy[y]) instanceof String) {
					Debug.println("processData: "+(String)data.get(valCopy[y]));
				}
                mDataModel.processData(data.get(valCopy[y]));
            }

            data.clear();
        }

        if (mDataModel.getRowCount() >0)
            mTable.setRowSelectionInterval(0,0);

        mModel.progressStop();
    }

    private void delete() {
        //get entry name
        mModel.progressStart();
        NameValuePairs obj = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        //send comment to server for the removal of user
        try {
            mConnection.delete(mDestination,
                               ScopeDef.SC_AUTH_IMPLS,
                               obj.getValue(IMPL_NAME));
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        mModel.progressStop();
        //send comment to server and refetch the content
        refresh();
    }

}
