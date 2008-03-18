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
import com.netscape.management.client.console.*;
import com.netscape.admin.certsrv.security.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;
import java.awt.*;
import java.util.*;
import java.io.*;
import javax.swing.*;
import java.awt.event.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import javax.swing.plaf.*;
import com.netscape.admin.certsrv.keycert.*;
import com.netscape.admin.certsrv.config.install.*;
import com.netscape.admin.certsrv.managecert.*;

/**
 * Encryption panel used for setup server encryption options. 
 * This is a wrapper class that emulates the CMSBaseTab API
 * calls.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class CMSEncryptionPanel extends CMSBaseTab  {

    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "ENCRYPTION";
    private ConsoleInfo mConsoleInfo;
    private CMSServerInfo mServerInfo;
    private AdminConnection mConnection;
    private JPanel mEncryptPane;
    private JComboBox mSelection, mTokenList, mCertList;
    private Hashtable mCertMapping;         //maps the function list items to tags
    private String mSelectedItem, mSelectedToken, mSelectedCert;           
    private JButton mWizard, mCipherPref, mSetup;   
    private Hashtable mTokenCertList;        //container for tokens and certs (Vector)
    private boolean mIsDomestic = false;    
    private boolean mHasFortezza =  false;
    private Vector mCipherPrefStore;
    private CMSCipherPreferenceDialog mCipherDialog;
    private boolean updateFlag = false;
    private boolean mSelectionIgnore = false;
    private boolean mWarningOn = false;
    private static final String HELPINDEX =
      "configuration-system-encryption-help";
    
    /**=========================================================
     * constructors
     * @param parent the parent panel
     * @see com.netscape.admin.certsrv.config.CMSTabPanel
     *==========================================================*/
    public CMSEncryptionPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mConsoleInfo = parent.getResourceModel().getConsoleInfo();
        mServerInfo = parent.getResourceModel().getServerInfo();
        mConnection = mServerInfo.getAdmin();
        mCertMapping = new Hashtable();
        mTokenCertList = new Hashtable();
        mCipherPrefStore = new Vector();
        mHelpToken = HELPINDEX;
    }
    
    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * Actual Instanciation of the UI components
     */
    public void init() {
        Debug.println("EncryptionPanel: init()");
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        mCenterPanel.setLayout(gb);
        
        //certificate settings
        JPanel top = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        top.setLayout(gb2);
        top.setBorder( new CompoundBorder(
            BorderFactory.createTitledBorder(
                mResource.getString("ENCRYPTION_BORDER_CERT_LABEL")), 
            new EmptyBorder(-3,
                            0,
                            DIFFERENT_COMPONENT_SPACE - 3,
                            0)));
                            
        //add selection combobox
        JLabel label1 = makeJLabel("SELECT");
        mSelection = new JComboBox();
        updateCertSelection();                  //dynamically generate this list
        addTopEntryField(top, label1, mSelection, gbc);
        if (mSelection.getItemCount()>0) {
            mSelection.setSelectedIndex(0);
            mSelectedItem = (String) mSelection.getSelectedItem();
        } else {
            //disable if nothing there
            mSelection.setEnabled(false);    
        }
        mSelection.addItemListener(this);
        
        //add encryption panel
        mEncryptPane = createCertEntry();
        //mEncryptPane = new InnerEncryptionPane(mConsoleInfo);
        //mEncryptPane.addEncryptionPaneListener(this);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,
                COMPONENT_SPACE,0,COMPONENT_SPACE);
        gb2.setConstraints(mEncryptPane, gbc);
        top.add(mEncryptPane);
        
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(top, gbc);
        mCenterPanel.add(top);
        
        mWizard = makeJButton("WIZARD");
        mCipherPref = makeJButton("CIPHERPREF");
        mSetup = makeJButton("SETUP");
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        //addButtonEntryField(mCenterPanel, mSetup, mWizard, mCipherPref, gbc);
        addButtonEntryField(mCenterPanel, mSetup, mWizard, gbc);
        //addButtonEntryField(mCenterPanel, mCipherPref, gbc);
        
        /* retrieve data from server and
         * feed data into mEncryptionPane for display ...
         */
        refresh();
    }
    
    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback() {
        if (mWarningOn) {
            String errorMsg = 
              mResource.getString(mPanelName+"_LABEL_WARNING_LABEL");
            JOptionPane.showMessageDialog(new JFrame(), errorMsg, "Warning",
              JOptionPane.WARNING_MESSAGE,
              CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON));
            mWarningOn = false;
            return false;
        }

        //save current changes if modified
        saveChanges((String) mSelection.getSelectedItem());
        
        //construct NVP parameters
        NameValuePairs nvp = new NameValuePairs();
        for (Enumeration e = mCertMapping.keys() ; e.hasMoreElements() ;) {
            CipherEntryData data = 
                (CipherEntryData)mCertMapping.get(e.nextElement());
            nvp.add(data.getTagName(),data.getTokenName()+","+data.getCertName());
        }
        
        if (updateCertMap(nvp)) {
            mWarningOn = false;
            clearDirtyFlag();
            return true;
        }
        
        return false;    
    }

    /**
     * Implementation for reset values
     * @return true if reset successful; otherwise, false.
     */
    public boolean resetCallback() {
        refresh();
        mWarningOn = false;
        return true;
    }

    /**
     * retrieve data from server and
     * feed data into mEncryptPane for display ...
     * refresh the panel and update data
     */
    public void refresh() {
        
        //call server to get the encryption settings
        NameValuePairs response;
        try {
            response = updateSecurityInformation();
        } catch(EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParent.getResourceModel().getFrame(), mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }
        
        //setup the data and UI
        updateFlag = true;
        cleanup();
        setupDataContainer(response);
        setupComboSelection();
        updateFlag = false;
        
        clearDirtyFlag();
    }

    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
/*
        if (e.getSource().equals(mSetup)) {
            Debug.println("Configure cert");
            InstallWizardInfo info = new InstallWizardInfo();
            InstallWizard wizard = new InstallWizard(
              mParent.getResourceModel().getFrame(), info);
            return;
        }
*/
       if (e.getSource().equals(mSetup)) {
            ManageCertDialog manageDialog = 
              new ManageCertDialog(mParent.getResourceModel().getFrame());
            manageDialog.showDialog(mParent.getResourceModel().getServerInfo().getAdmin());
       }
       if (e.getSource().equals(mWizard)) {
            Debug.println("Wizard");
            
            //XXX launch OUR OWN wizard 
            CertSetupWizardInfo info = new
				CertSetupWizardInfo(mConnection, mConsoleInfo);
            CertSetupWizard wizard = new CertSetupWizard(mParent.getResourceModel(), info);
            //  mParent.getResourceModel().getFrame(), info);
            //KeyCertWizard wizard = new KeyCertWizard(mConnection);
            
            //XXX we should update the settings to reflect the changes
            
            
            return;
       } 
       if (e.getSource().equals(mCipherPref)) {
            Debug.println("Wizard");
            
            if (mCipherDialog == null) {
                mCipherDialog = new CMSCipherPreferenceDialog(mParent.mModel.getFrame(),
                        mIsDomestic, 
                        mHasFortezza, 
                    CMSCipherPreferenceDialog.SSL2|CMSCipherPreferenceDialog.SSL3);
            
            }
       
            refresh();
            setupCipherDialog(mCipherDialog);
            
            mCipherDialog.show();
            
            if (!mCipherDialog.isModified())
                return;
            
            //Save the cipher settings
            StringBuffer buf = new StringBuffer();
            
            if (mCipherDialog.isSSLEnabled(mCipherDialog.SSL2)) {
                String[] v2 = mCipherDialog.getSSLPreference(mCipherDialog.SSL2);
                for (int i=0; i< v2.length; i++) {
                    if (mCipherDialog.isCipherEnabled(v2[i])) {
                        if (buf.length()>0)
                            buf.append(",");
                        buf.append(v2[i]);
                    }
                }
            }
            
            if (mCipherDialog.isSSLEnabled(mCipherDialog.SSL3)) {
                String[] v3 = mCipherDialog.getSSLPreference(mCipherDialog.SSL3);
                for (int i=0; i< v3.length; i++) {
                    if (mCipherDialog.isCipherEnabled(v3[i])) {
                        if (buf.length()>0) 
                            buf.append(",");
                        buf.append(v3[i]);
                    }
                }
            }
            
            updateCipherPref(buf.toString());
            
            //save the new settings
            mCipherDialog.setSaved(true);
            
            return;
       }
    }
    
    //== ItemListener ==
    public void itemStateChanged(ItemEvent e){
        
        if (e.getSource().equals(mSelection)) {
            if (e.getStateChange() == e.SELECTED) {
                if (!mSelectionIgnore) {
                    updateFlag = true;
                    saveChanges(mSelectedItem);
                    mSelectedItem = (String) mSelection.getSelectedItem();
                    setupComboSelection();
                    updateFlag = false;
                }
            }
        } else if (e.getSource().equals(mTokenList)) {
            if ( (!updateFlag) && (e.getStateChange() == e.SELECTED) ){
                Debug.println("Token Selected");
                setDirtyFlag();
                updateFlag = true;
                setupCertCombo();
                updateFlag = false;
            }
        } else if (e.getSource().equals(mCertList)) {
            if ( (!updateFlag) && (e.getStateChange() == e.SELECTED) ){
                Debug.println("Cert Selected");
                saveChanges(mSelectedItem);
                setupComboSelection();
                setDirtyFlag();
            }
        }
        mWarningOn = true;
    }
    
    /*==========================================================
     * Private Methods
     *==========================================================*/
    
    //save the mappings if changes made
    private void saveChanges(String entry) {
        if ( (!mSelectedToken.equals((String)mTokenList.getSelectedItem())) ||
             (!mSelectedCert.equals((String)mCertList.getSelectedItem())) ) {
            
            CipherEntryData data = (CipherEntryData) mCertMapping.get(entry);
            data.setData((String)mTokenList.getSelectedItem(),
                         (String)mCertList.getSelectedItem());
        }
    }

    //cleanup the 
    private void cleanup() {
        mTokenCertList.clear();
        mCipherPrefStore.removeAllElements();
        mTokenList.removeAllItems();
        mCertList.removeAllItems();
    }
    
    //setup the cipher dialog
    private void setupCipherDialog(CMSCipherPreferenceDialog dialog) {
        Debug.println("setupCipherDialog");
        dialog.setSSLEnabled(dialog.SSL3,true);
        
        //set selected/unselected ciphers
        String[] v2 = dialog.getSSLPreference(dialog.SSL2);

        if (v2.length <= 0)
            dialog.setSSLEnabled(dialog.SSL2,false);
        else
            dialog.setSSLEnabled(dialog.SSL2,true);

        for (int i=0; i< v2.length; i++) {
            if (mCipherPrefStore.contains(v2[i])) {
                //Debug.println("setEnable: "+v2[i]);
                dialog.setCipherEnabled(v2[i], true);
            } else {
                //Debug.println("setDisable: "+v2[i]);
                dialog.setCipherEnabled(v2[i], false);
            }
        }
        String[] v3 = dialog.getSSLPreference(dialog.SSL3);
        if (v3.length <= 0)
            dialog.setSSLEnabled(dialog.SSL3,false);
        else
            dialog.setSSLEnabled(dialog.SSL3,true);

        for (int i=0; i< v3.length; i++) {
            if (mCipherPrefStore.contains(v3[i])) {
                //Debug.println("setEnable: "+v3[i]);
                dialog.setCipherEnabled(v3[i], true);
            } else {
                //Debug.println("setDisable: "+v3[i]);
                dialog.setCipherEnabled(v3[i], false);
            }
        }
        
        mCipherDialog.setSaved(true);
    }
    
    //initialize the data containers
    private void setupDataContainer(NameValuePairs response) {
        
        //setup security version flag
        String version = response.getValue(Constants.PR_CIPHER_VERSION);
        if ( (version != null) && (version.equals(
            Constants.PR_CIPHER_VERSION_DOMESTIC)) ) {
            mIsDomestic = true;            
        }
        
        //setup fortezza flag
        String fortezza = response.getValue(Constants.PR_CIPHER_FORTEZZA);
        if ( (fortezza != null) && (fortezza.equalsIgnoreCase("TRUE")) ){
            mHasFortezza = true;            
        }
        
        //setup cipher preference settings
        String cipherpref = response.getValue(Constants.PR_CIPHER_PREF);
        //Debug.println("cipher preference: "+cipherpref);
        if ( (cipherpref != null) && (!cipherpref.trim().equals("")) ) {
            StringTokenizer tokenizer = new StringTokenizer(cipherpref, ",");
            while (tokenizer.hasMoreTokens()) {
                String pref = tokenizer.nextToken().trim();
                //Debug.println("Add cipher: "+pref);
                mCipherPrefStore.addElement(pref);
            }
        } else {
            Debug.println("ERROR: CMSEncryptionPanel: setupDataContainer()- no cert pref list");       
        }
        
        //setup the cipher entry data - loop through table and retrieve
        //the current mappings
        mSelectionIgnore = true;
        for (Enumeration e = mCertMapping.keys() ; e.hasMoreElements() ;) {
            String name = (String) e.nextElement();
            CipherEntryData data = (CipherEntryData)mCertMapping.get(name);
            String value = response.getValue(data.getTagName());
            if ( (value != null) && (!value.trim().equals("")) ) {
                StringTokenizer tokenizer = new StringTokenizer(value, ",");
                try {
                    String token = tokenizer.nextToken().trim();
                    String cert = tokenizer.nextToken().trim();
                    data.setData(token, cert);
                } catch(Exception ex) {    
                    Debug.println("ERROR: CMSEncryptionPanel: setupDataContainer()- no token/cert not complete");
                }
            } else {
               Debug.println("ERROR: CMSEncryptionPanel: setupDataContainer()- no token/cert for:"+data.getTagName());
               mCertMapping.remove(name);
               mSelection.removeItem(name);
               Debug.println("RECOVER: CMSEncryptionPanel: setupDataContainer()- "+name+" removed from selection");
            }
        }
        mSelectionIgnore = false;
        
        //setup the token-cert list data table
        String tokenlist = response.getValue(Constants.PR_TOKEN_LIST);
        if ( (tokenlist != null) && (!tokenlist.trim().equals("")) ) {
            StringTokenizer tokenizer = new StringTokenizer(tokenlist, ",");
            while (tokenizer.hasMoreTokens()) {
                String token = tokenizer.nextToken().trim();
                Debug.println("Token: "+token);
                
                //get the certificate associated with this token
                String certList = response.getValue(Constants.PR_TOKEN_PREFIX+token);
                Vector certVector = new Vector();
                if ( (certList != null) && (!certList.trim().equals("")) ) {
                    StringTokenizer tokenizer2 = new StringTokenizer(certList, ",");
                    while (tokenizer2.hasMoreTokens()) {
                        certVector.addElement(tokenizer2.nextToken().trim());
                    }
                } else {
                    Debug.println("WARNING: CMSEncryptionPanel: setupDataContainer()- no certlist for: "+token);   
                }
                
                //set the token-cert to hashtable
                mTokenCertList.put(token, certVector);
                mTokenList.addItem(token);
            }
        } else {
            Debug.println("ERROR: CMSEncryptionPanel: setupDataContainer()- no tokenlist");   
        }
        
        //setup the initial combobox selection
        String newToken = (String) mTokenList.getSelectedItem();
        mSelectedToken = newToken;
        mCertList.removeAllItems();
        Vector list = (Vector) mTokenCertList.get(newToken);
        for (int i=0; i< list.size(); i++)
            mCertList.addItem(list.elementAt(i));    
    }
    
    //setup combobox selection
    private void setupComboSelection() {
        //get current function selection
        CipherEntryData data = (CipherEntryData) mCertMapping.get(mSelection.getSelectedItem());
        
        //select correct token from the token list
        String oldToken = (String) mTokenList.getSelectedItem();
        String newToken = data.getTokenName();
        if (!oldToken.equals(newToken)) {
            mTokenList.setSelectedItem(newToken);
            mSelectedToken = newToken;
            setupCertCombo();
        }
        //select correct certiicate from the cert list
        mCertList.setSelectedItem(data.getCertName());
        mSelectedCert = data.getCertName();
    }
    
    //setup the certlist combo
    private void setupCertCombo() {
        String newToken = (String) mTokenList.getSelectedItem();
        mCertList.removeAllItems();
        Vector list = (Vector) mTokenCertList.get(newToken);
        for (int i=0; i< list.size(); i++)
            mCertList.addItem(list.elementAt(i));
    }
    
    //creating the certificate mapping UI components
    private JPanel createCertEntry() {
        JPanel panel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        panel.setLayout(gb);
        
        //set border
        panel.setBorder( new CompoundBorder(
            BorderFactory.createTitledBorder(mResource.getString("ENCRYPTION_BORDER_MAPTO_LABEL")), 
            new EmptyBorder(-3,
                            0,
                            CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                            0)));
                            
        //add components
        mTokenList = new JComboBox();
        mTokenList.addItemListener(this);
        mCertList = new JComboBox();
        mCertList.addItemListener(this);
        JLabel label1 = makeJLabel("TOKEN");
        JLabel label2 = makeJLabel("CERTIFICATE");
        CMSAdminUtil.addEntryField(panel, label1, mTokenList, label2, mCertList, gbc);
        return panel;
    }
     
    /**
     * The certificates used by each subsystem are stored as cert list
     * strings in the resource file using the PR_ prefix tags.
     */
    private void updateCertSelection() {
        //get installed subsystem     
        Vector v = mServerInfo.getInstalledSubsystems();

        //add default system certificate list
        String certs;
        try {
                certs = mResource.getString("ENCRYPTION_SERVER_CERTS");
        } catch (MissingResourceException e) {
                Debug.println("ERROR: unable retrieving server default cert list");
                certs = "";
        }
        if (!certs.trim().equals("")) {
            StringTokenizer tokenizer = new StringTokenizer(certs, ",");
            while (tokenizer.hasMoreTokens()) {
                String certname = tokenizer.nextToken().trim();
                loadCertList(certname);
            }
        }
        
        //create additional subsystem certificate list
        for (int i=0; i< v.size(); i++) {
            String name = (String)v.elementAt(i);
            try {
                String certlist = mResource.getString(PANEL_NAME+"_"+name+"_CERTS");
                    if (!certlist.trim().equals("")) {
                        StringTokenizer tokenizer = new StringTokenizer(certlist, ",");
                        while (tokenizer.hasMoreTokens()) {
                            String certname = tokenizer.nextToken().trim();
                            loadCertList(certname);
                        }
                    }
            } catch (MissingResourceException e) {
                Debug.println("ERROR: unable retrieving subsystem certificate list: "+name);    
            }
        }        
    }
    
    //register the certificate and mapping entry
    private void loadCertList(String certTag) {
        //add to selection list
        String name;
        try {
            name = mResource.getString("ENCRYPTION_COMBOBOX_SELECT_VALUE_"+certTag);
        } catch (MissingResourceException e) {
            Debug.println("ERROR: cert resource not found: "+certTag);
            return;
        }
        mSelection.addItem(name);
        mCertMapping.put(name, new CipherEntryData(certTag));
    }

    private static void addTopEntryField(JPanel panel, JComponent label, 
      JComponent field, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add( label, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                        0,DIFFERENT_COMPONENT_SPACE);
        panel.add( field, gbc );
    }

   private static void addButtonEntryField(JPanel panel, 
      JComponent field, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.NORTHEAST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        //gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        panel.add(new JLabel(""));

        gbc.gridx++;
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,
         //                               0,DIFFERENT_COMPONENT_SPACE);
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                        0,COMPONENT_SPACE);
        panel.add( field, gbc );
    }       

    private static void addButtonEntryField(JPanel panel, JComponent label, 
      JComponent field, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.NORTHEAST;
        //gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        panel.add(new JLabel(""));
        
        gbc.gridx++;
        gbc.weightx = 1.0;
        panel.add( label, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,
                                        //0,DIFFERENT_COMPONENT_SPACE);
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                        0,COMPONENT_SPACE);
        panel.add( field, gbc );
    }       

    private static void addButtonEntryField(JPanel panel, JComponent label, 
      JComponent field, JComponent field1, GridBagConstraints gbc) {
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.NORTHEAST;
        //gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,0,0);
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,0);
        panel.add(new JLabel(""));
        
        gbc.gridx++;
        gbc.weightx = 1.0;
        panel.add( label, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        //gbc.gridwidth = gbc.REMAINDER;
        //gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,
         //                               0,DIFFERENT_COMPONENT_SPACE);
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                        0,COMPONENT_SPACE);
        panel.add( field, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE,DIFFERENT_COMPONENT_SPACE,
         //                               0,DIFFERENT_COMPONENT_SPACE);
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
                                        0,COMPONENT_SPACE);
        panel.add( field1, gbc );
    }       

    /*==========================================================
     * SEND STUFF TO SERVER 
     *==========================================================*/    
 
    //retrieve security information from the server side
    private NameValuePairs updateSecurityInformation() 
        throws EAdminException
    {
        Debug.println("Get Security Information");
        NameValuePairs nvp = new NameValuePairs();
        nvp.add(Constants.PR_CIPHER_PREF,"");
        nvp.add(Constants.PR_CIPHER_VERSION,"");
        nvp.add(Constants.PR_CIPHER_FORTEZZA,"");
        nvp.add(Constants.PR_TOKEN_LIST,"");
        
        //create installed certificate list data request
        for (Enumeration e = mCertMapping.elements(); e.hasMoreElements() ;) {
            CipherEntryData data = (CipherEntryData)e.nextElement();
            nvp.add(data.getTagName(),"");
        }
        
        NameValuePairs response;
        
        response = mConnection.read(DestDef.DEST_SERVER_ADMIN,
                           ScopeDef.SC_ENCRYPTION,
                           Constants.RS_ID_CONFIG,
                           nvp);  
        
        Debug.println("Received: "+response.toString());
        
        return response;
    }
    
    //modify cipher preference
    private void updateCipherPref(String list) {
        Debug.println("Set Cipher Preference: "+list);
        
        NameValuePairs nvp = new NameValuePairs();
        nvp.add(Constants.PR_CIPHER_PREF, list);
        
        //send to server
        try {
            mConnection.modify(DestDef.DEST_SERVER_ADMIN,
                               ScopeDef.SC_ENCRYPTION,
                               Constants.RS_ID_CONFIG,
                               nvp);
        } catch(EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParent.getResourceModel().getFrame(), mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }
    }
    
    //modify certificate mapping
    private boolean updateCertMap(NameValuePairs config) {
        Debug.println("Set Certificate Mapping: "+config.toString());
        
        //send to server
        try {
            mConnection.modify(DestDef.DEST_SERVER_ADMIN,
                               ScopeDef.SC_ENCRYPTION,
                               Constants.RS_ID_CONFIG,
                               config);
        } catch(EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParent.getResourceModel().getFrame(), mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }
        
        return true;
    }    
    
}

//internal data structure
class CipherEntryData {
    
    String mTag;
    String mToken;
    String mCert;
    
    public CipherEntryData(String tag) {
        mTag = tag;
    }
    
    public void setData(String token, String cert) {
        mToken = token;
        mCert = cert;
    }
    
    public String getCertName() {
        return mCert;    
    }
    
    public String getTokenName() {
        return mToken;    
    }
    
    public String getTagName() {
        return mTag;    
    }
    
    public String toString() {
        return mTag+"-"+mToken+":"+mCert;    
    }

}
