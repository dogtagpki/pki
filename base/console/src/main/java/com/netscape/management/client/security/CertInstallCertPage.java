/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.security;


import com.netscape.management.client.components.Wizard;
import com.netscape.management.client.components.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.net.*;
import java.io.*;
import java.util.jar.*;
import javax.swing.*;
import javax.swing.event.*;
import netscape.ldap.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.security.csr.*;
import com.netscape.management.client.preferences.*;
import com.netscape.management.nmclf.*;

class CertInstallCertPage extends WizardPage implements SuiConstants, ActionListener, DocumentListener {

    JRadioButton certInText, certInFile, certFromCAPlugin;
    JTextField certFilename = new JTextField();
    JTextArea certText = new JTextArea();

    JButton paste, browse;

    ResourceSet resource;

    public void insertUpdate(DocumentEvent e) {
        changedUpdate(e);
    }

    public void removeUpdate(DocumentEvent e) {
        changedUpdate(e);
    }

    public void changedUpdate(DocumentEvent e) {
        if (e.getDocument().equals(certFilename.getDocument()) ||
            e.getDocument().equals(certText.getDocument())) {
            setEnableNextButton();
        }
    }

    void setEnableNextButton() {
        if ((certInFile.isSelected() && (certFilename.getText().length() > 0)) ||
            (certInText.isSelected() && (certText.getText().length() > 0)) ||
            (certFromCAPlugin.isSelected())) {
            m_canMoveForward = true;
        } else {
            m_canMoveForward = false;
        }

        ((WizardDataCollectionModel)getDataModel()).fireChangeEvent();
    }

    ICAPlugin ic;

    public boolean nextInvoked() {
        boolean canGoNext = true;

        if (certInText.isSelected()) {
            getDataModel().setValue("dercert", certText.getText());
        } else if (certFromCAPlugin.isSelected()) {
            int status = ic.checkPendingRequest();

            Debug.println("Check request status:"+status);

            if (status == ICAPlugin.STATUS_ISSUED) {
                //query plugin for a certificate
                getDataModel().setValue("dercert", ic.getCertificateData());
            } else if (status == ICAPlugin.STATUS_QUEUED) {
                //query plugin and resave the session back
                //ask plugin for some ui, or don't continue.
                //if plugin doesn't provide an ui we should just pop up our own ui.
                return false;
            } else if (status == ICAPlugin.STATUS_ERROR) {
                //ask plugin for some ui pages
                return false;
            }
        } else if (certInFile.isSelected()) {
            boolean invalidFile = false;
            try {
                File f = new File(certFilename.getText());

                RandomAccessFile raf = new RandomAccessFile(f, "rw");
                byte[] data = new byte[(int)(raf.length())];
                raf.readFully(data, 0, (int)(raf.length()));

                String dercertString = new String(data);
                if ((dercertString.indexOf("-----BEGIN CERTIFICATE-----") == -1) ||
                    (dercertString.indexOf("-----END CERTIFICATE-----") == -1))
                {
                    invalidFile = true;
                }


                getDataModel().setValue("dercert", new String(data));
            } catch (Exception e) {
                invalidFile = true;
            }

            if (invalidFile) {
                //display error message and do not continue
                Dialog owner = (Dialog) SwingUtilities.getAncestorOfClass(Dialog.class, this);
                ErrorDialog errorDialog = 
		  new ErrorDialog(owner,
				  resource.getString("CertInstallCertPage", "invalidFileTitle"),
				  resource.getString("CertInstallCertPage", "invalidFileExplain"));
                errorDialog.hideDetail();
                errorDialog.show();
                return false;
            }
        }

        Wizard wizard = (Wizard) SwingUtilities.getAncestorOfClass(Wizard.class, this);
        try {
            if (wizard != null) {
                wizard.setBusyCursor(true);
            }
            Hashtable args = new Hashtable();
            args.put("formop", "INSTALL_CERT");

            //if installmethod is any none null value
            //then the cgi will attempt to add cert.
            //args.put("installmethod", "1");
            args.put("sie"      , getDataModel().getValue("sie"));
            args.put("tokenname", getDataModel().getValue("tokenname"));
            args.put("dercert"  , getDataModel().getValue("dercert"));
            args.put("certtype" , getDataModel().getValue("certtype"));
            args.put("trust_flag", "0");

            ConsoleInfo consoleInfo = (ConsoleInfo)(getDataModel().getValue("consoleInfo"));

            AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
                                                  "admin-serv/tasks/configuration/SecurityOp"),
                                          consoleInfo.getAuthenticationDN(),
                                          consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            admTask.exec();
            Debug.println(admTask.getResultString().toString());


            if (!SecurityUtil.showError(admTask)) {
                getDataModel().setValue("certlist", new CertificateList(admTask.getResultString().toString()));
            } else {
                canGoNext = false;
            }

        } catch (Exception e) {
            SecurityUtil.printException("CertInstallCertPage::nextInvoked()",e);
            canGoNext = false;
        }
        finally {
            if (wizard != null) {
                wizard.setBusyCursor(false);
            }
        }              

        return canGoNext;
    }

    public void actionPerformed(ActionEvent event) {
        if (event.getActionCommand().equals("PASTE")) {
            certText.paste();
        } else if (event.getActionCommand().equals("BROWSE")) {
            JFileChooser jfChooser = new JFileChooser();
            if (jfChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    certFilename.setText(jfChooser.getSelectedFile().getCanonicalPath());
                    validate();
                    repaint();
                } catch (Exception e) {
                    SecurityUtil.printException("CertInstallCertPage::actionPerformed(...)",e);
                }
            }
        } else if (event.getSource().equals(certFromCAPlugin)) {
            certText.setEnabled(false);
            certFilename.setEnabled(false);

            setEnableNextButton();
        } else if (event.getSource().equals(certInFile)) {
            certFilename.setEnabled(true);
            certText.setEnabled(false);

            setEnableNextButton();
        }  else if (event.getSource().equals(certInText)) {
            certFilename.setEnabled(false);
            certText.setEnabled(true);

            setEnableNextButton();
        }
    }

    public void pageShown() {
        if ( getDataModel().getValue("certtype").equals(Integer.toString(CertInstallWizard.CA))) {
            certFromCAPlugin.setEnabled(false);
        }
    }

    public void helpInvoked() {
	KeyCertUtility.getHelp().contextHelp("CertInstallCertPage", "help");
    }

    public CertInstallCertPage(ConsoleInfo consoleInfo) {
        super(KeyCertUtility.getResourceSet().getString("CertInstallCertPage", "pageTitle"));
        setLayout(new GridBagLayout());

        resource = KeyCertUtility.getResourceSet();

        //need to do some pre-setup here
        String caPluginLabel = resource.getString("CertInstallCertPage", "certFromCAPluginLabel");
        certFromCAPlugin = new JRadioButton("", false);
        certFromCAPlugin.setText(caPluginLabel);
        certFromCAPlugin.addActionListener(this);


        try {
            //check to see if there is an cached session
            LDAPSearchResults searchResults =
                consoleInfo.getLDAPConnection().search("cn=LiveSession, cn=CSRSession,"+consoleInfo.getCurrentDN(),
                                                       LDAPConnection.SCOPE_SUB,
                                                       "(objectclass=*)",
                                                       null, false);

            if (searchResults.hasMoreElements()) {
                //does have a cached session should attempt to load plugin and see if it can get the certificate
                LDAPPreferences pref = new LDAPPreferences(consoleInfo.getLDAPConnection(),
                                                           "LiveSessionPluginJar",
                                                           "cn=CSRSession,"+consoleInfo.getCurrentDN()
                                                           );

                String jarFilename = pref.getString("jarname");

                JarFile jarfile = new JarFile(jarFilename);
                Manifest mf = jarfile.getManifest();
                Map map = mf.getEntries();

                Set set = mf.getEntries().keySet();
                Iterator iterator = set.iterator();
                while (iterator.hasNext()) {
                    String className = (String)(iterator.next());
                    //System.out.println(className);
                    Attributes attr = mf.getAttributes(className);

                    certFromCAPlugin.setText(caPluginLabel+" "+attr.getValue("Description"));

                    try {
                        Debug.println("Loading plugin");
                        LocalJarClassLoader loader = new LocalJarClassLoader(jarFilename);

                        Class myClass = loader.loadClass(className.substring(0, className.indexOf(".class")));

                        ic = (ICAPlugin)(myClass.newInstance());

                        pref = new LDAPPreferences(consoleInfo.getLDAPConnection(),
                                                   "LiveSession",
                                                   "cn=CSRSession,"+consoleInfo.getCurrentDN()
                                                   );

                        Debug.println("Restore session data");
                        Enumeration names_enum = pref.getNames();
                        while (names_enum.hasMoreElements()) {
                            String name = names_enum.nextElement().toString();
                            ic.setProperty(name, pref.getString(name));
                        }


                    } catch (Exception e) {
                        SecurityUtil.printException("CertInstallCertPage::CertInstallCertPage(...)",e);
                        Debug.println("CertInstallCertPage: unable to restore session data");
                    }
                }
            } else {
                //does not have any cached session we will disable install cert via plugin
                certFromCAPlugin.setEnabled(false);
            }
        } catch (Exception e) {
            Debug.println("CertInstallCertPage: error in retriving session data");
            certFromCAPlugin.setEnabled(false);
        }


        certInFile = new JRadioButton(resource.getString("CertInstallCertPage", "certInFileLabel"), false);
        certInFile.addActionListener(this);

        certInText = new JRadioButton(resource.getString("CertInstallCertPage", "certInTextLabel"), true);
        certInText.addActionListener(this);

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(certFromCAPlugin);
        buttonGroup.add(certInFile);
        buttonGroup.add(certInText);

        browse = JButtonFactory.create(resource.getString("CertInstallCertPage", "browseLabel"), this, "BROWSE");
        browse.setToolTipText(resource.getString("CertInstallCertPage", "browse_tt"));
        paste = JButtonFactory.create(resource.getString("CertInstallCertPage", "pasteFromClipboardLabel"), this, "PASTE");
        paste.setToolTipText(resource.getString("CertInstallCertPage", "pasteFromClipboard_tt"));
        
        JLabel whereIsCert = new JLabel(resource.getString("CertInstallCertPage", "whereIsCert"));

        certText.getDocument().addDocumentListener(this);
        certFilename.getDocument().addDocumentListener(this);

        int y = 0;

        GridBagUtil.constrain(this, whereIsCert,
                              0, ++y, 3, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(this, certFromCAPlugin,
                              0, ++y, 3, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);


        JPanel p = new JPanel();
        {
            p.setLayout(new GridBagLayout());
            GridBagUtil.constrain(p, certInFile,
                                  0, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.NONE,
                                  0, 0, 0, 0);

            GridBagUtil.constrain(p, certFilename,
                                  1, 0, 1, 1,
                                  1.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, 0, COMPONENT_SPACE);

            GridBagUtil.constrain(p, browse,
                                  2, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.EAST, GridBagConstraints.NONE,
                                  0, 0, 0, 0);
        }

        GridBagUtil.constrain(this, p,
                              0, ++y, 3, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, certInText,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

        GridBagUtil.constrain(this, paste,
                              2, y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE,
                              0, 0, COMPONENT_SPACE, 0);

        JScrollPane certTextScrollPane = new JScrollPane(certText,
                                                         JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                                         JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        certTextScrollPane.setBorder(UIManager.getBorder("TextField"));
        GridBagUtil.constrain(this, certTextScrollPane,
                              0, ++y, 3, 1,
                              1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);
        
        certFilename.getAccessibleContext().
            setAccessibleDescription(resource.getString("CertInstallCertPage", "certInFile_tt"));
        
        certText.getAccessibleContext().
            setAccessibleDescription(resource.getString("CertInstallCertPage", "certInText_tt"));
    
    }

    /*public static void main(String arg[]) {
        JFrame f = new JFrame();
        f.getContentPane().add("North", new CertInstallCertPage(new ConsoleInfo()));
        f.setSize(400,400);
        f.show();
     }*/

}
