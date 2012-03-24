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

import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;
import org.mozilla.jss.CryptoManager;
/**
 * User Certs Tab
 *
 * @author Khai Truong
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class TKSKeysTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "TKSKEYS";
    private CryptoManager mCryptoManager = null;
    
	private AdminConnection mConnection;
    private String mDestination;
    private CMSBaseResourceModel mModel;
    private ConsoleInfo mConsoleInfo;
    private JComboBox mToken;   
    protected JScrollPane mScrollPane;
    protected JTable mTable;                    //table
    protected ListKeysModel mDataModel;   //table model
    protected KeyCreateDialog mEditor=null;      //keep single copy
    
    protected JButton mRefresh, mAdd, mHelp;
    private final static String HELPINDEX = "configuration-log-plugin-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public TKSKeysTab(CMSBaseResourceModel model, String destination) {
        super(PANEL_NAME, model);
        mConnection = model.getServerInfo().getAdmin();
        mModel = model;
        mConsoleInfo = mModel.getConsoleInfo();
        mDataModel = new ListKeysModel();
        mDestination = destination;
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
        if (e.getSource().equals(mHelp)) {
            helpCallback();
        }
        if (e.getSource().equals(mAdd)) {
		            if (mEditor==null)
            mEditor = new KeyCreateDialog(mModel.getFrame(),mConnection);
			mEditor.setToken((String)mToken.getSelectedItem());
            mEditor.showDialog(mDestination, ScopeDef.SC_LOG_IMPLS);

            //CertSetupWizardInfo info = new CertSetupWizardInfo(mConnection, mConsoleInfo);

            // if it is "0", then it means it is root cert mode.
            // if it is "1", then it means it is user cert mode.
            //info.setMode("1");
            //CertSetupWizard wizard = new CertSetupWizard(
            //  mModel, info);
            refresh();
            return;
        }

        int row = mTable.getSelectedRow();
        if(row < 0)
            return;

  
    
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
        mTable.repaint(1);
    }

    /**
     * create the user action button panel
     */
    protected JPanel createButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
 
		
		mAdd = makeJButton("ADD");

        JButton[] buttons = {mAdd};
        JButtonFactory.resize( buttons );
		JPanel rightPanel = CMSAdminUtil.makeJButtonVPanel( buttons );

        return rightPanel;
    }

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        //JButton[] buttons = { mRefresh, mHelp };
        JButton[] buttons = { mRefresh };
        return makeJButtonPanel(buttons, true);
    }

    protected JPanel createListPanel() {
        mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

        mToken = new JComboBox();
        mToken.setPreferredSize(new java.awt.Dimension(54, 22));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
		gbc.gridheight = 1;
		gbc.gridwidth = gbc.REMAINDER;
		gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE*30);
		gb.setConstraints(mToken, gbc);        
        mListPanel.add(mToken);
   

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
        gbc.gridheight = 10;
        gbc.weighty = 1.0;
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
 
        NameValuePairs response=null;
        try {
            response = mConnection.search(mDestination,
              ScopeDef.SC_TOKEN, new NameValuePairs()); 
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
        }
		if (response != null) {
			mToken.removeAllItems();
			String[] vals = new String[response.size()];
			int i=0;
            for (String entry : response.keySet()) {
				vals[i++] = entry.trim();
			}
        
			int sindex = 0;
			CMSAdminUtil.quickSort(vals, 0, response.size()-1);
			for (i=0; i<vals.length; i++) {
				Vector v = new Vector();
				String entry = vals[i];
				String value = response.get(entry);
				// look for the comma separator
				
				StringTokenizer st = new StringTokenizer(value, ",");
                while (st.hasMoreTokens()) {
                    String currentToken= st.nextToken();
                    mToken.addItem(currentToken);
                }

			}
		}

        refresh();

        return mListPanel;
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
    }


    //set buttons
    private void setButtons() {
        
        //enable and diable buttons accordingly
        //Debug.println("setButtons() - "+mTable.getSelectedRow());
        //Debug.println("setButtons() - "+mTable.getSelectionModel().isSelectionEmpty());

        
    }
    
    //=============================================
    // SEND REQUESTS TO THE SERVER SIDE
    //=============================================
    private void update() {
        //send request and parse data
        
        mModel.progressStart();
        
        NameValuePairs response;
        NameValuePairs request;
        request = new NameValuePairs();
        request.put(Constants.PR_TOKEN_LIST, (String) mToken.getSelectedItem());
        try {
            response = mConnection.search(mDestination,
              ScopeDef.SC_TKSKEYSLIST, request); 
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        Debug.println(response.toString());

        //parse the data
        mDataModel.removeAllRows();
        if (response != null) {
            String[] vals = new String[response.size()];
            int i=0;
            for (String entry : response.keySet()) {
                vals[i++] = entry.trim();
            }
            
            int sindex = 0;
            CMSAdminUtil.quickSort(vals, 0, response.size()-1);
            for (i=0; i<vals.length; i++) {
                String entry = vals[i];
                if (entry.equals(Constants.PR_TOKEN_LIST)) {
                    String value = response.get(entry);
                    // look for the comma separator
                    StringTokenizer st = new StringTokenizer(value, ",");
                    int numberOfKeys = 0;
                    while (st.hasMoreTokens()) {
                        Vector v = new Vector();
                        String currentKey = st.nextToken();
                        v.addElement(currentKey);
                        numberOfKeys++;
                        mDataModel.addRow(v);
                    }
                    if(numberOfKeys==0)
                    {
                        Vector v = new Vector();
                        String currentKey = new String("empty list");
                        v.addElement(currentKey);
                        mDataModel.addRow(v);
                    }
                }
            }
            mTable.setRowSelectionInterval(0,0);
        }


			mModel.progressStop();
		}

    private void delete() {
        mModel.progressStart();
        int row = mTable.getSelectedRow();
        String nickname = (String)(mDataModel.getValueAt(row, 3))+":"+
          (String)(mDataModel.getValueAt(row, 0));
        String id = nickname+":SERIAL#<"+mDataModel.getValueAt(row, 1)+">"
          +mDataModel.getValueAt(row, 2);
        
        //send comment to server for the removal of user
        try {
            mConnection.delete(mDestination, ScopeDef.SC_USERCERTSLIST, id);
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
