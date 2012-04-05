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
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * LDAP Mapper Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class PanelMapperConfigDialog extends JDialog
    implements ActionListener, ItemListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "MAPPERCONFIGDIALOG";

    private JFrame mParentFrame;
    private ResourceBundle mResource;
    protected  ConfigTableModel mDataModel;
    protected boolean mIsOK = false;
    protected NameValuePairs mData;
    private JScrollPane mScrollPane;
    private JTable mTable;
    private String mRuleName;
    private String mDest;
    private String mScope;  //SC_USERCERT or SC_CACERT
    private AdminConnection mConn;
    private JButton mOK, mCancel, mHelp;
    private JComboBox mSelection;

    private static final String CAHELPINDEX =
      "configuration-ldappublish-camapper-dbox-help";
    private static final String RAHELPINDEX =
      "configuration-ldappublish-ramapper-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public PanelMapperConfigDialog(JFrame parent, AdminConnection conn) {
        super(parent,true);
        mConn = conn;
        mParentFrame = parent;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new ConfigTableModel();
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
    public void showDialog(String name, String destination, String scope) {
        mIsOK = false;

        mDataModel.removeAllRows();
        mData = new NameValuePairs();
        mRuleName = name;
        mDest = destination;
        mScope = scope;
        Debug.println("MapperConfigDialog: showDialog() - mapper: "+
            mRuleName+" dest: "+mDest+" scope: "+mScope);

        if (!refresh(name))
            return;

        this.show();
    }

    public boolean isOK() {
        return mIsOK;
    }

    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {

            //save any current edit component
            Component component = mTable.getEditorComponent();
            if (component!= null) {
                int col = mTable.getEditingColumn();
                int row = mTable.getEditingRow();
                if ((col>-1)&&(row>-1)) {
                    String str = ((JTextComponent)component).getText();
                    mTable.setValueAt(str, row, col);
                }
            }

            try {
                saveConfiguration();
            } catch (EAdminException e) {
                //display error dialog
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                return;
            }

            mIsOK = true;
            this.dispose();
        }

        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }
        if (evt.getSource().equals(mHelp)) {
            if (mDest.equals(DestDef.DEST_CA_ADMIN))
                CMSAdminUtil.help(CAHELPINDEX);
            else if (mDest.equals(DestDef.DEST_RA_ADMIN))
                CMSAdminUtil.help(RAHELPINDEX);
        }
    }

    //== ItemListener ==
    public void itemStateChanged(ItemEvent e){
        if (e.getSource().equals(mSelection)) {
            if (e.getStateChange() == e.SELECTED) {
                //take care of current editing
                mTable.getColumnModel().getColumn(1).
                    getCellEditor().stopCellEditing();
                Debug.println("Selected: "+ (String) mSelection.getSelectedItem());
                setupConfigUI((String) mSelection.getSelectedItem());
            }
        }
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    private void saveEdit() {

        //save any current edit component
        Component component = mTable.getEditorComponent();

    }

    //setup and refresh the UI components
    private boolean refresh(String mapperName) {

        //get mapper listing
        if (!getMapperListing(mapperName))
            return false;

        //setup UI
        if (! setupConfigUI(mapperName))
            return false;

        return true;
    }

    //retrieve the mapper class listing and update
    //the selection UI
    private boolean getMapperListing(String mapperName) {
        NameValuePairs response;

        try {
            response = getMapperList();
        }catch (EAdminException e) {
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                e.toString(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }

        Debug.println("MapperList: "+response.toString());
        mSelection.removeAllItems();

        for (String name : response.keySet()) {
            mSelection.addItem(name.trim());
        }

        mSelection.setSelectedItem(mapperName);
        return true;
    }

    //retrieve the config parameters for the mapper
    //and update the config UI
    private boolean setupConfigUI(String mapperName) {

        try {
            mData = getConfiguration(mapperName);
        }catch (EAdminException e) {
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                e.toString(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }
        Debug.println("MapperConfigDialog: showDialog() config: "+mData.toString());

        mDataModel.removeAllRows();

        for (String entry : mData.keySet()) {
            entry = entry.trim();
            if (!entry.equals(Constants.PR_MAPPER)) {
                String value = mData.get(entry);
                Vector<String> v = new Vector<String>();
                v.addElement(entry);
                v.addElement(value);
                mDataModel.addRow(v);
            }
        }
       mScrollPane.repaint();
       mTable.repaint();
       return true;
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

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "IMPLNAME", null);
        mSelection = new JComboBox();
        mSelection.addItemListener(this);
        addEntryField(mListPanel, label3, mSelection, gbc);

        //left side certificate table
        mTable = new JTable(mDataModel);
        mScrollPane = JTable.createScrollPaneForTable(mTable);
        //mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PANEL_NAME,"USERS"));
        mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        //mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        //setLabelCellRenderer(mTable,1);
        setCellEditor(mTable,1);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE,
                                0,CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        return mListPanel;
    }

    //Set the index column's cellrender as label cell
    private void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
            new DefaultTableCellRenderer());
    }

    //set the index column's cell editor
    private void setCellEditor(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellEditor(
            new DefaultCellEditor(new JTextField()));
    }

    //retrieve the mapper listing from the server side
    private NameValuePairs getMapperList()
        throws EAdminException
    {
        return mConn.search(mDest, getMapperScope(),
                            new NameValuePairs());
    }

    //retrieve the configuration parameters for specific
    //mapper class
    private NameValuePairs getConfiguration(String mapper)
        throws EAdminException
    {
       return mConn.read(mDest, getMapperScope(),
                         mapper, new NameValuePairs());
    }

    //get the mapper scope
    private String getMapperScope() {

        if (mScope.equals(ScopeDef.SC_CACERT))
            return ScopeDef.SC_CAMAPPER;
        else
            return ScopeDef.SC_USERMAPPER;
    }

    //save the configuration settings for the mapper
    private void saveConfiguration() throws EAdminException {
        NameValuePairs nvp = getData();
        nvp.put(Constants.PR_MAPPER, (String) mSelection.getSelectedItem());
        mConn.modify(mDest, mScope, Constants.RS_ID_CONFIG, nvp);
    }

    private NameValuePairs getData() {
        NameValuePairs response = new NameValuePairs();
        for (int i=0; i< mDataModel.getRowCount(); i++) {
            response.put((String) mDataModel.getValueAt(i, 0),
                    (String) mDataModel.getValueAt(i, 1));
        }
        return response;
    }

    /**
     * Add a label and a textfield to a panel, assumed to be using
     * GridBagLayout.
     */
    private static void addEntryField(JPanel panel, JComponent label,
      JComponent field, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE,0,0);
        panel.add( label, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE,
                                0,CMSAdminUtil.COMPONENT_SPACE);
        panel.add( field, gbc );
    }
}
