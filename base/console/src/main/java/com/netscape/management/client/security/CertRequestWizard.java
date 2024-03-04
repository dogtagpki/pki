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

import java.awt.Component;
import java.awt.Dialog;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.io.File;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.net.URL;

import javax.swing.ButtonGroup;
import javax.swing.DefaultListCellRenderer;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import com.netscape.management.client.security.csr.ICAPlugin;
import com.netscape.management.client.security.csr.IUIPage;
import com.netscape.management.client.util.ModalDialogUtil;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.MultilineLabel;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.LocalJarClassLoader;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.AdmTask;
import com.netscape.management.client.util.Help;
import com.netscape.management.client.util.Browser;
import com.netscape.management.client.preferences.LDAPPreferences;
import com.netscape.management.client.components.ErrorDialog;
import com.netscape.management.client.components.IDataCollectionModel;
import com.netscape.management.client.components.IWizardSequenceManager;
import com.netscape.management.client.components.Wizard;
import com.netscape.management.client.components.WizardDataCollectionModel;
import com.netscape.management.client.components.WizardPage;
import com.netscape.management.client.components.WizardSequenceManager;
import com.netscape.management.client.console.Console;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.nmclf.SuiConstants;
import com.netscape.management.nmclf.SuiScrollPane;

import netscape.ldap.*;

/**
 * Certificate request wizard.
 * 
 * Certificate request will guide user through the process
 * to request certificate from a CA.
 *
 * for design detail see: http://kingpin/console/4.5/security/request.htm
 * 
 * @see com.netscape.management.client.security.CertInstallWizard
 */
public class CertRequestWizard  {

    Wizard wizardDialog;
    IWizardSequenceManager sequenceManager = new WizardSequenceManager();
    IDataCollectionModel dataCollectionModel = new WizardDataCollectionModel();

    final String PLUGIN_ID          = "PLUGIN_ID";
    final String PLUGIN_DIR         = Console.PREFERENCE_DIR + "caplugin" + File.separator;
    final String DEFAULT_PLUGIN_CLASS = "com.netscape.management.client.security.csr.DefaultPlugin.class";
    final String DEFAULT_PLUGIN_DESC  = "Manual Cert Request Plugin";

    PluginWizardPage pwdPage = null;
    PluginWizardPage endSequence = null;
    ICAPlugin ic;

    int pageCount = 0;

    ResourceSet resource;
    Help help;

    //if true then we don't need to care
    //about saving the session
    boolean defaultPluginUsed = true;

    String selectedPluginJarFilename;
    
    public String i18n(String s) {
	return resource.getString("CertRequestWizard", s);
    }

    //this is a wrapper for IRequestPage, we need to encapsulate it into
    //an IWizardContentPage, so we can add this page to wizard.
    class PluginWizardPage extends WizardPage {
	public IUIPage _iContentPage;


	public PluginWizardPage(IUIPage iContentPage) {
	    super(iContentPage.getPageName());

	    _iContentPage = iContentPage;
	    
	    setLayout(new GridBagLayout());

	    GridBagUtil.constrain(this, iContentPage.getComponent(), 
				  0, 0, 1, 1, 
				  1.0, 1.0, 
				  GridBagConstraints.NORTH, GridBagConstraints.BOTH,
				  0, 0, 0, 0);
	}


	public void helpInvoked() {
	    String helpString = _iContentPage.getHelpURL();
	    Debug.println(helpString);
	    try {
	        URL url = new URL(helpString);
		Browser browser = new Browser();
		if (!(browser.open(url, Browser.EXISTING_WINDOW))) {
		    //unable to launch any default browser display error here;
		    JOptionPane.showMessageDialog(this, 
						  i18n("noBrowser"),
						  i18n("noBrowserExplain"), 
						  JOptionPane.INFORMATION_MESSAGE); 
		}
	    } catch (Exception e) {
		help.contextHelp(helpString, "help");
	    }
	}


	public boolean canMoveForward() {
	    return _iContentPage.isPageValidated();
	}

	public boolean backInvoked() {
	    _iContentPage.getPreviousPage();
	    boolean moveBackOk = super.backInvoked();

	    if (moveBackOk && (pageCount != 0)) {
		pageCount--;
	    }

	    return moveBackOk;
	}


	public boolean nextInvoked() {
	    //add next page here
	    IUIPage _nextPage = _iContentPage.getNextPage();

	    //if user return the same page we should not continue.
	    if (_nextPage ==  _iContentPage) {
		return false;
	    }

	    if (_nextPage != null) {
		wizardDialog.addPage(_nextPage.getPageName(), new PluginWizardPage(_nextPage));
		sequenceManager.setNext(_iContentPage.getPageName(), _nextPage.getPageName());
	    } else if (_iContentPage instanceof TokenPasswordPage) {
		//call server to get pkcs#10
		String pkcs10 = "";

		Hashtable args = new Hashtable();
		args.put("formop", "GENERATE_CSR");
		args.put("sie", getDataModel().getValue("sie", ""));
		args.put("keypwd", getDataModel().getValue("keypwd"));
		args.put("dn", ic.getCertificateDN());
		args.put("tokenname", getDataModel().getValue("tokenname"  , ""));

                String keysize = ic.getProperty("keysize");
                if (keysize != null) {
                    args.put("keysize", keysize);
                }

                String signingalgo = ic.getProperty("signingalgo");
                if (signingalgo != null) {
                    args.put("signingalgo", signingalgo);
                }

		ConsoleInfo consoleInfo = (ConsoleInfo)(getDataModel().getValue("consoleInfo"));


		AdmTask admTask = null;

		try {
		    admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
						  "admin-serv/tasks/configuration/SecurityOp"),
					  consoleInfo.getAuthenticationDN(),
					  consoleInfo.getAuthenticationPassword());
		} catch (Exception e) {
		    SecurityUtil.printException("CertRequestWizard::PluginWizardPage::nextInvoked()",e);	
		}

		admTask.setArguments(args);

		wizardDialog.setBusyCursor(true);
		admTask.exec();
		wizardDialog.setBusyCursor(false);

		Debug.println(admTask.getResultString().toString());

		int submitStatus;

		if (!SecurityUtil.showError(admTask)) {
		    //pkcs#10 to submit
		    String result = admTask.getResultString().toString();

		    String header = "-----BEGIN NEW CERTIFICATE REQUEST-----";
		    String footer = "-----END NEW CERTIFICATE REQUEST-----";
		    if (false) {
			header = "-----BEGIN RENEWAL CERTIFICATE REQUEST-----";
			footer = "-----END RENEWAL CERTIFICATE REQUEST-----";
		    }

		    String  _cert = result.substring(result.indexOf(header), 
						     result.indexOf(footer)+footer.length());

		    //submit csr
		    submitStatus = ic.submitCSR(_cert);

		    if ((submitStatus == ICAPlugin.STATUS_ERROR) ||
			(submitStatus == ICAPlugin.STATUS_QUEUED)) {
			//just save the session, only do it for none default plugin
			if (!defaultPluginUsed) {
			    try {
				LDAPPreferences pref = new LDAPPreferences(consoleInfo.getLDAPConnection(),
									   "LiveSession",
									   "cn=CSRSession,"+consoleInfo.getCurrentDN()
									   );

				Enumeration names_enum = ic.getPropertyNames();
				while (names_enum.hasMoreElements()) {
				    String attr = names_enum.nextElement().toString();
				    pref.set(attr, ic.getProperty(attr));
				}

				pref.save();

				pref = new LDAPPreferences(consoleInfo.getLDAPConnection(),
							   "LiveSessionPluginJar",
							   "cn=CSRSession,"+consoleInfo.getCurrentDN()
									   );
				pref.set("jarname", selectedPluginJarFilename);
				pref.save();

			    } catch (Exception e) {
				SecurityUtil.printException("CertRequestWizard::PluginWizardPage::nextInvoked()",e);
				Debug.println("unable to save session.");
			    }
			}

			//it is an error plugin will provide the ui
			wizardDialog.addPage(endSequence.getStepName(), endSequence);
			sequenceManager.setNext(pwdPage.getStepName(), endSequence.getStepName());
			
		    } else  if (submitStatus == ICAPlugin.STATUS_ISSUED) {
			//get the cert and install it.
			//then show the status
			//probably want to queue it too.

			args.clear();
			args.put("formop", "INSTALL_CERT");
			args.put("installmethod", "1" );
			args.put("certtype", Integer.toString(CertInstallWizard.SERVER));
			args.put("dercert", ic.getCertificateData());
			try {
                wizardDialog.setBusyCursor(true);
			    admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
							  "admin-serv/tasks/configuration/SecurityOp"),
						  consoleInfo.getAuthenticationDN(),
						  consoleInfo.getAuthenticationPassword());

			    admTask.setArguments(args);

			    admTask.exec();
			    Debug.println(admTask.getResultString().toString());

			    if (SecurityUtil.showError(admTask)) {
				return false;
			    }
			    
			} catch (Exception unableToInstallCert) {
			    SecurityUtil.printException("CertRequestWizard::PluginWizardPage::nextInvoked()",unableToInstallCert);
			    return false;
            }finally {
                wizardDialog.setBusyCursor(false);
            }
		    }

		    //queue the information
		    //perhaps we should some how lump this with the
		    //pkcs#10 gen together?
		} else {
		    return false;
		}

	    } else if (_iContentPage instanceof StatusPage) {
		//should be the end the page
	    } else  {
		//password page, this assume next page is null, and next page is
		//not StatusPage, and current page is not a password page.
		wizardDialog.addPage(pwdPage.getStepName(), pwdPage);
		sequenceManager.setNext(getStepName(), pwdPage.getStepName());
	    }



	    if ((_nextPage == null) && sequenceManager.getNext(getStepName()).equals(pwdPage.getStepName())) {
		((TokenPasswordPage)(pwdPage._iContentPage)).setRemainingPageCount(_iContentPage.getRemainingPageCount());
	    } else  if (canMoveForward()) {
		pageCount++;
	    }

	    return canMoveForward();
	}

	public int getMaxSteps() {
	    return _iContentPage.getRemainingPageCount()+pageCount+3;
	}
    }

    //the initaial page of the wizard that allow user to select
    //how they would like to request certificate.
    class CAPlugin extends WizardPage implements FilenameFilter, ListSelectionListener, ActionListener {
	JRadioButton manual, ca;
	JList pluginList;
	PluginItem defaultPlugin;
	//int maxSteps;

	class PluginItem extends JPanel {
	    public String _className, _description, _updateURL, _userUrl, _jarFilename;
	    public ImageIcon _image = null;
	    public PluginItem(String className,
			      String description,
			      String updateURL,
			      byte[] imageData,
			      String userUrl,
			      String jarFilename) {
		super();
		_className    = className;
		_description  = description;
		_updateURL    = updateURL;
		if (imageData != null) {
		    _image        = new ImageIcon(imageData);
		}
		_userUrl          = userUrl;
		_jarFilename  = jarFilename;

		add(new JLabel(description), "West");
		//add(new JLabel(_image), "Center");
	    }
	}

	public boolean accept(File dir, String name) {
	    return name.endsWith(".jar") && (name.indexOf("_en") == -1);
	}

	public CAPlugin() {
	    super(KeyCertUtility.getResourceSet().getString("CertRequestWizard", "pageTitle"));
	    
	    setLayout(new GridBagLayout()); 

	    m_canMoveForward = true;

	    manual = new JRadioButton(resource.getString("CertRequestWizard", "manualReq"), true);
	    manual.addActionListener(this);

	    ca     = new JRadioButton(resource.getString("CertRequestWizard", "pluginReq"), true);
	    ca.addActionListener(this);

	    ButtonGroup  bGroup = new ButtonGroup();
	    bGroup.add(manual);
	    bGroup.add(ca);

	    int y = 0;
	    GridBagUtil.constrain(this, new MultilineLabel(resource.getString("CertRequestWizard", "explain")),
				  1, y,  1, 1, 
				  1.0, 0.0,
				  GridBagConstraints.NORTH, GridBagConstraints.BOTH,
				  0, 0, SuiConstants.COMPONENT_SPACE, 0);

	    GridBagUtil.constrain(this, manual,
				  1, ++y,  1, 1, 
				  1.0, 0.0,
				  GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
				  0, 0, 0, 0);

	    GridBagUtil.constrain(this, ca,
				  1, ++y,  1, 1, 
				  1.0, 0.0,
				  GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
				  0, 0, SuiConstants.COMPONENT_SPACE, 0);

	    //construct plugin list
	    Vector caList = new Vector();
	    File f = new File(PLUGIN_DIR);

            // Load the default plugin
            defaultPlugin = new PluginItem(DEFAULT_PLUGIN_CLASS, DEFAULT_PLUGIN_DESC,
                                           "", null , "", null);

            // Check if caplugin directory exists
             if (!f.exists())
                f.mkdir();

            // Check for additional plugins
	    File[] fList = f.listFiles(this);
	    for (int i=0; i<fList.length; i++) {
		// load jar file and extract all the information
		// about each jar.
		try {
		    //System.out.println(fList[i].getParent()+"/"+fList[i].getName());
		    String jarFilename = fList[i].getParent()+"/"+fList[i].getName();
		    JarFile jarfile = new JarFile(jarFilename); 
		    Manifest mf = jarfile.getManifest();

		    Set set = mf.getEntries().keySet();
		    Iterator iterator = set.iterator();
		    while (iterator.hasNext()) {
			String className = (String)(iterator.next());
			//System.out.println(className);
			Attributes attr = mf.getAttributes(className);

			//get image off the jar file
			ZipEntry imageEntry =  jarfile.getEntry(attr.getValue("Icon"));
			byte[] imageData = null;

			if (imageEntry != null) {
			    //System.out.println(imageEntry.getSize());

			    InputStream is = jarfile.getInputStream(imageEntry);

			    int pos = 0;
			    //add 1 so is.available() will return 0 which ends the loop
			    int bytesLeftToRead = (int)imageEntry.getSize()+1;
			    imageData = new byte[bytesLeftToRead]; 
			    while (is.available() > 0) { 
				int bytesRead = is.read(imageData, pos, bytesLeftToRead); 
				pos += bytesRead;
				bytesLeftToRead -= bytesRead;
			    }
			}

			Debug.println("Plugin Jar: " + jarFilename);
                        Debug.println("Class Name: " + className);
			Debug.println("Description: " + attr.getValue("Description"));
			Debug.println("Update URL: " + attr.getValue("UpdateURL"));
			Debug.println("User URL: " + attr.getValue("UserURL"));

			PluginItem tmp = new PluginItem(className,
							attr.getValue("Description"),
							attr.getValue("UpdateURL"), 
							imageData, 
							attr.getValue("UserURL"), 
							jarFilename);
			caList.addElement(tmp);
		    }
		} catch (Exception ee) {
		    SecurityUtil.printException("CertRequestWizard::CAPlugin::CAPlugin()",ee);
		}
	    }
	    if (caList.size()==0) {
		ca.setEnabled(false);
	    }
	    pluginList = new JList(caList);
	    pluginList.setEnabled(false);
	    pluginList.setCellRenderer(
				       new DefaultListCellRenderer() {
		public Component getListCellRendererComponent(JList list,
							      Object value,
							      int modelIndex,
							      boolean isSelected,
							      boolean cellHasFocus) {

		    setIcon(((PluginItem)value)._image);

		    return super.getListCellRendererComponent(list, 
							      ((PluginItem)value)._description, 
							      modelIndex, 
							      isSelected, 
							      cellHasFocus);
		}
	    });

	    pluginList.addListSelectionListener(this);
	    //pluginList.setEnabled(false);
	    //pluginList.addListSelectionListener(this);

	    GridBagUtil.constrain(this, new SuiScrollPane(pluginList),
				  1, ++y,  1, 1,
				  1.0, 1.0,
				  GridBagConstraints.NORTH, GridBagConstraints.BOTH,
				  0, 0, 0, 0);

	    pwdPage = new PluginWizardPage(new TokenPasswordPage(dataCollectionModel));
	}

	public void actionPerformed(ActionEvent l) {
	    try {
		if (l.getSource() == manual) {
		    pluginList.setEnabled(false);
		} else if (l.getSource() == ca) {
		    if (pluginList.getSelectedIndex() == -1) {
			pluginList.setSelectedIndex(0);
		    }
		    pluginList.setEnabled(true);
		}
		getDataModel().setValue("selectedPlugin", pluginList.getSelectedValue());
		validate();
		repaint();
	    } catch (Exception e) {
		SecurityUtil.printException("CertREquestWizard::CAPlugin::actionPerformed(...)",e);
	    }
	}

	
	PluginItem currentSelectedPlugin = null;
	public void valueChanged(ListSelectionEvent e) {
	    getDataModel().setValue("selectedPlugin", pluginList.getSelectedValue());
	}
    
	public boolean nextInvoked() {
	    //add next page here
	    PluginItem selectedPlugin = (PluginItem)(getDataModel().getValue("selectedPlugin", defaultPlugin));
	    defaultPluginUsed = (selectedPlugin == defaultPlugin);

	    if ((currentSelectedPlugin == null)  ||
		!(currentSelectedPlugin.equals(selectedPlugin))) {
		currentSelectedPlugin = selectedPlugin;

		String className = selectedPlugin._className.substring(0, selectedPlugin._className.indexOf(".class"));

		try {
                    Class myClass;
                    // If this is the default plugin, just load the class directly
                    if (defaultPluginUsed) {
                        myClass = Class.forName(className);
                    } else {
		        LocalJarClassLoader loader = new LocalJarClassLoader(selectedPlugin._jarFilename);
		        myClass = loader.loadClass(className);
                    }

		    ic = (ICAPlugin)(myClass.newInstance());

		    PluginWizardPage firstPage = new PluginWizardPage(ic.getUIPageSequence(ICAPlugin.UI_BEGINING_SEQUENCE));
		    endSequence = new PluginWizardPage(ic.getUIPageSequence(ICAPlugin.UI_ENDING_SEQUENCE));

		    wizardDialog.addPage(firstPage.getStepName(), firstPage);

		    getSequenceManager().setNext(PLUGIN_ID, firstPage.getStepName());

		    selectedPluginJarFilename = selectedPlugin._jarFilename;
		} catch (Exception e) {
		    SecurityUtil.printException("CertRequestWizard::CAPlugin::nextInvoked()",e);
		}
	    }

	    return true;
	}

	public int getMaxSteps() {
	    return 5;
	}

	public void helpInvoked() {
	    help.contextHelp("CertRequestWizard", "help");
	}
    }

    /**
     * Create a instance of the certifificate request wizard.
     *
     * ***WARNING***
     * This wizard use a plugin model, it assume there is a ./caplugin directory
     * on where this wizard is lunched.  under that directory it must contain a 
     * "default.jar" which provide manual cert request ui.
     * ***WARNING***
     *
     * to implement your own plugin see: http://kingpin/console/4.5/security/ca.htm
     *
     * @param parent component from where this wizard was lunched
     * @param consoleInfo information required for this wizard to contact admin server inorder to generate key pair and CSR
     * @param sie server instance name (ie. admin-serve-HOSTNAME)
     * @param tokenName token to use, key pair will be generated using the token specified, and token is also where the cert will probably be install to.
     *
     * @see com.netscape.management.client.security.CertInstallWizard
     */
    public CertRequestWizard(Component parent,
			     ConsoleInfo consoleInfo,
			     String sie, 
                             String tokenName) {

	Dialog owner = (Dialog)SwingUtilities.getAncestorOfClass(Dialog.class, parent);
	wizardDialog = new Wizard(owner,
				  KeyCertUtility.getResourceSet().getString("CertRequestWizard", "title"),
				  true, 
				  sequenceManager,
				  dataCollectionModel);
	Debug.println(parent.toString());

	//instantiate a session information
	try {
	    //create CSRSession if it doesn't already exist
	    LDAPPreferences.createPreferenceEntry(consoleInfo.getLDAPConnection(),
						 "CSRSession",
						 consoleInfo.getCurrentDN());

	    resource = KeyCertUtility.getResourceSet();
	    help = new Help(resource);


	    //check to see if there is an cached session
	    LDAPSearchResults searchResults =
		consoleInfo.getLDAPConnection().search("cn=LiveSession, cn=CSRSession,"+consoleInfo.getCurrentDN(),
						       LDAPConnection.SCOPE_SUB, 
						       "(objectclass=*)",
						       null, false);

	    //if an cached session exist we should ask user if it is ok to remove
	    //it.  Currently we only support one single session cached
	    //per request.
	    if (searchResults.hasMoreElements()) {
		ErrorDialog warning = new ErrorDialog((parent instanceof Frame)?(Frame)parent:null, 
						      resource.getString("CertRequestWizard", "removeSessionTitle"), 
						      resource.getString("CertRequestWizard", "removeSession"), 
						      null,
						      resource.getString("CertRequestWizard", "removeSessionDetail"),
						      ErrorDialog.YES_NO,
						      ErrorDialog.YES);

		warning.setIcon(ErrorDialog.WARNING_ICON);
		warning.setVisible(true);

		if (warning.getButtonClicked()==ErrorDialog.NO) {
		    //if user says no then cert request should
		    //not be able to pop up.
		    canSetVisible = false;
		} else {
		    //remove cache if user says ok.
		    try {
			LDAPPreferences pref = new LDAPPreferences(consoleInfo.getLDAPConnection(),
						   "LiveSession",
						   "cn=CSRSession,"+consoleInfo.getCurrentDN()
						   );
			pref.delete();

			pref = new LDAPPreferences(consoleInfo.getLDAPConnection(),
						   "LiveSessionPluginJar",
						   "cn=CSRSession,"+consoleInfo.getCurrentDN()
						   );
			pref.delete();
		    } catch (Exception e) {
			SecurityUtil.printException("CertRequestWizard::CertRequestWizard(...)",e);
			Debug.println("unable to remove the cached session");
		    }
		}
	    }
	} catch (Exception e) {
	    Debug.println("No live session");
	}

	dataCollectionModel.setValue("tokenname"  , tokenName);
	dataCollectionModel.setValue("sie"        , sie.toLowerCase());
	dataCollectionModel.setValue("consoleInfo", consoleInfo);

	//get the first page
	//on the first page, depends on what user select it will
	//load the correct ca page information and continue.
        try {
            wizardDialog.addPage(PLUGIN_ID, new CAPlugin());
        }catch (Exception e) {
	    SecurityUtil.printException("CertRequestWizard::CertRequestWizard(...)",e);
        }


        wizardDialog.setSize(500, 350);
        //wizardDialog.setVisible(true);

        if (!(parent instanceof Frame)) {
            ModalDialogUtil.setDialogLocation(wizardDialog,parent);
        }
    }
    boolean canSetVisible = true;

    /**
     * Show or hide certificate request wizard
     *
     * @param visible if true wizard will be lunched
     */
    public void setVisible(boolean visible) {
        wizardDialog.setVisible(visible&&canSetVisible);
    }
}

