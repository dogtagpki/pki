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
import com.netscape.admin.certsrv.ug.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Plugin Instances Management Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public abstract class CMSPluginInstanceTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    protected static String PANEL_NAME = null;
    protected static String RULE_NAME = null;
    protected static String RULE_STAT = null;
    protected static String RULE_IMPL = null;
    protected static String RULE_TYPE = null;
	
    
    protected AdminConnection mConnection;

    protected JScrollPane mScrollPane;
    protected JTable mTable;                    //table
    protected CMSRuleDataModel mDataModel;   //table model
    protected String mDestination;              //dest flag
	protected String mScope;
    protected String mId = null;    // used as a ip id for crl exts

    protected JButton mRefresh, mEdit, mAdd, mDelete, mOrder, mHelp;
    protected static String RAHELPINDEX = null;
    protected static String CAHELPINDEX = null;
    protected static String KRAHELPINDEX = null;
    protected static String OCSPHELPINDEX = null;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSPluginInstanceTab(CMSBaseResourceModel model, String dest,
			String panelName) {
        super(panelName, model);
		Debug.println("CMSPluginInstanceTab::CMSPluginInstanceTab(<model>,"+dest+","+panelName+")");
        mConnection = model.getServerInfo().getAdmin();
        mDestination = dest;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /*==========================================================
	 * EVENT HANDLER METHODS
     *==========================================================*/

	public CMSBaseConfigDialog makeEditConfigDialog(
				NameValuePairs nvp,
                JFrame parent,
                AdminConnection conn,
                String dest
				)
        {
                // make it possible to use a different dialog for
                // edit operation
                return makeNewConfigDialog(nvp, parent, conn, dest);
        }

	public abstract CMSBaseConfigDialog makeNewConfigDialog(
				NameValuePairs nvp,
                JFrame parent,
                AdminConnection conn,
                String dest
				);

	public abstract PluginSelectionDialog getPluginSelectionDialog(
				JFrame parent,
				AdminConnection conn,
				String dest,
				CMSPluginInstanceTab pluginType
				);

	/**
	 * Can override this to handle more events if needed
	 */
	public void moreActionPerformed(ActionEvent e)
	{
		return;
	}

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            Debug.println("Refresh");
            refresh();
        }
        if (e.getSource().equals(mEdit)) {
            if(mTable.getSelectedRow()< 0)
                return;
            NameValuePairs data = (NameValuePairs)
                mDataModel.getObjectValueAt(mTable.getSelectedRow());

            NameValuePairs response;
            mModel.progressStart();
            try{
                response = getConfig();
            } catch (EAdminException ex1) {
                showErrorDialog(ex1.getMessage());
                mModel.progressStop();
                return;
            }
            mModel.progressStop();
            Debug.println(response.toString());
            
			CMSBaseConfigDialog dialog = makeEditConfigDialog(
				response,
				mModel.getFrame(),
				mModel.getServerInfo().getAdmin(),
				mDestination);
				
			dialog.setModel(mModel);
			dialog.setInstanceScope(mScope);
            dialog.showDialog(response, data.get(RULE_NAME));
            
            if(!dialog.isOK()) return;

            refresh();    
        }
        
        if (e.getSource().equals(mAdd)) {
            Debug.println("Add");
            PluginSelectionDialog dialog = 
				getPluginSelectionDialog(
					mModel.getFrame(),
					mConnection,
					mDestination,
					this
					);

			dialog.setModel(mModel);
            dialog.showDialog();
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
		moreActionPerformed(e);
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
    }

    /**
     * create the user action button panel
     */
    protected JPanel createUserButtonPanel() {
		Debug.println("CMSPluginInstanceTab::createUserButtonPanel()");
        //edit, add, delete, help buttons required
        //actionlister to this object
        mEdit = makeJButton("EDIT");
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
		JButton[] buttons = {mAdd, mDelete, mEdit};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    protected JPanel createActionPanel() {
		Debug.println("CMSPluginInstanceTab::createActionPanel()");
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
	//JButton[] buttons = { mRefresh, mHelp };
	JButton[] buttons = { mRefresh };
		return makeJButtonPanel( buttons , true);
    }

    protected JPanel createListPanel() {
		Debug.println("CMSPluginInstanceTab::createListPanel()");
		try {
		mListPanel = new JPanel();
		GridBagLayout gb = new GridBagLayout();
	    GridBagConstraints gbc = new GridBagConstraints();
		mListPanel.setLayout(gb);

		//center table
		mTable = new JTable(mDataModel);
		mScrollPane = JTable.createScrollPaneForTable(mTable);
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

	    JPanel buttonPanel = createUserButtonPanel();
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

		Debug.println("returning from CMSPluginInstanceTab::createListPanel()");

		} catch (Exception e3) {
			Debug.println("e3: caught exception:");
            if (Debug.isEnabled())
				e3.printStackTrace();
		}
		return mListPanel;
    }

	//Set the first column's cellrender as label cell
	protected void setLabelCellRenderer(JTable table, int index) {
		Debug.println("Table.getColumnModel = "+table.getColumnModel());
	    table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
	}
	
    //Set the first column's cellrender as label cell
	protected void setLabelCellEditor(JTable table, int index) {
	    table.getColumnModel().getColumn(index).setCellRenderer(new PasswordCellRenderer());
	    table.getColumnModel().getColumn(index).setCellEditor(new DefaultCellEditor(new JPasswordField()));
	}


    //set buttons
    protected void setButtons() {
        
        //enable and diable buttons accordingly
        //Debug.println("setButtons() - "+mTable.getSelectedRow());
        
        if (mTable.getSelectionModel().isSelectionEmpty()) {
            mDelete.setEnabled(false);
            mEdit.setEnabled(false);
            return;
        }
        
        if(mDataModel.getRowCount()<=0) {
		    mDelete.setEnabled(false);
		    mEdit.setEnabled(false);
		    return;
		}
		
	    mDelete.setEnabled(true);
	    mEdit.setEnabled(true);
    }
    
	//=============================================
	// SEND REQUESTS TO THE SERVER SIDE
	//=============================================
	private void update() {
        //send request and parse data

        NameValuePairs response;
        NameValuePairs request = new NameValuePairs();
        if (mId != null && mId.length() > 0) {
            request.put(Constants.PR_ID, mId);
        }

        try {
			Debug.println("CMSPluginInstanceTab:update() ---- 1 --- ");
			Debug.println("mConnection = "+mConnection);
            response = mConnection.search(mDestination,
                                          mScope,
                                          request);
        } catch (EAdminException e) {
            //display error dialog
			if (Debug.isEnabled())
				e.printStackTrace();
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        Debug.println(response.toString());

		/* 	format of each data element:
			plugin;visibility;enabled
				where plugin is the name of the plugin impl
				visibility is one of {visible,invisible}
				enabled is one of {enabled,disabled}
		*/

        for (String entry : response.keySet()) {
			String plugin="";
			String visibility=null;
			String enabled=null;

            entry = entry.trim();
            String value = response.get(entry);

			StringTokenizer st = new StringTokenizer(value,";");

			if (st.hasMoreElements()) {
				plugin = st.nextToken();
Debug.println("xxxxxxx plugin " + plugin);
				if (st.hasMoreElements()) {
					visibility = st.nextToken();
					if (st.hasMoreElements()) {
						enabled = st.nextToken();
					}
				}
			}

			if (visibility != null && visibility.equals("visible")) {

               	NameValuePairs data = new NameValuePairs();
		data.put(RULE_NAME, entry);
		data.put(RULE_IMPL, plugin);
				if (enabled != null) {
			data.put(RULE_STAT, enabled);
				}
               	mDataModel.processData(data);
			}
        }        

        if (mDataModel.getRowCount() >0)
            mTable.setRowSelectionInterval(0,0);
        
        mTable.invalidate();
        mTable.validate();
        mTable.repaint(1);
        mModel.progressStop();
    }

    private void delete() {
        
        mModel.progressStart();
        //get entry name
        NameValuePairs data = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        //send comment to server for the removal of user
        try {
            mConnection.delete(mDestination,
                               mScope,
                               data.get(RULE_NAME));
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

    //this returns the onfiguration
    private NameValuePairs getConfig() throws EAdminException {
        NameValuePairs data = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());
        NameValuePairs request = new NameValuePairs();
        if (mId != null && mId.length() > 0) {
            request.put(mId, "");
        }
            
        NameValuePairs response = mConnection.read(mDestination,
                                                   mScope,
                                                   data.get(RULE_NAME),
                                                   request);
        return response;
    }
    
   
}
