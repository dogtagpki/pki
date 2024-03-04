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

import java.awt.*;
import java.util.*;
import java.net.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.console.*;
import javax.swing.plaf.*;

/**
 *
 * Encryption panel used to configure server security settings.
 * Encyprtion panel will query the server and setup the appropirate
 * selection/options.  What individule server should do is 
 * implements IEncryptionOptions interface, which will allow encryption
 * panel to query settings/options for that specific servers.
 *
 * Individule is responsible to store their own encryption preferences.
 *
 * All changes occures under encryption panel will result in a change
 * interface been called. See IEncryptionOptions for more detail
 *
 * @see com.netscape.management.client.security.IEncryptionOptions
 *
 */
public class EncryptionPanel extends JPanel {
    
    JCheckBox securityEnabled;
    ConsoleInfo _consoleInfo;
    String _sie;
    Hashtable cipherFamilyList = new Hashtable();
    ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

    //if the setup is not complete don't make any call
    //to the abstract function.
    boolean setupComplete = false;

    IEncryptionOptions _encryptionOptions;

    Vector settings = new Vector();

    boolean initialSecurityEnabled;

    /**
     * Reset encryption options to initial settings
     */
    public void reset() {
	for (int i=0; i<settings.size(); i++) {
	    ((CipherFamilyPane)(settings.elementAt(i))).reset();
	}

	securityEnabled.setSelected(initialSecurityEnabled);
	enableAllCipherFamily(securityEnabled.isSelected());
    }

    /**
     * Call this function after the setting has been saved, so 
     * if reset is called it will not revert to the initial
     * value (value before it has been saved).
     */
    public void setSaved() {
	for (int i=0; i<settings.size(); i++) {
	    ((CipherFamilyPane)(settings.elementAt(i))).setSaved();
	}

	initialSecurityEnabled = securityEnabled.isSelected();
	enableAllCipherFamily(securityEnabled.isSelected());
    }


    private void enableAllCipherFamily(boolean enabled) {
	for (int i=0; i<settings.size(); i++) {
	    ((CipherFamilyPane)(settings.elementAt(i))).setEnabled(enabled);
	}
    }


    public EncryptionPanel(ConsoleInfo consoleInfo, String sie, EncryptionOptions encryptionOptions) {
	this(consoleInfo, sie, (IEncryptionOptions)encryptionOptions);
    }

    /**
     *
     * Create an encryption panel
     *
     * @param consoleInfo server sepcific information, encryption panel will use admin url, admin uid, adm password
     * @param sie server instance name (ie. admin-serve-HOSTNAME)
     * @param encryptionOptions interface that allow encryption panel to 
     *                             query for setting, and send change events when it occures
     */
    public EncryptionPanel(ConsoleInfo consoleInfo, String sie, IEncryptionOptions encryptionOptions) {
	super();
	setLayout(new GridBagLayout());

	_consoleInfo = consoleInfo;
	_sie = sie;
	_encryptionOptions = encryptionOptions;

	securityEnabled = new JCheckBox(resource.getString("EncryptionPanel", "sslEnabledLabel"));
	securityEnabled.setSelected(_encryptionOptions.isSecurityEnabled());
        securityEnabled.addActionListener(new ActionListener(){
	    public void actionPerformed(ActionEvent e) {
		if (EncryptionPanel.this.setupComplete) {
		    _encryptionOptions.securityEnabledChanged(securityEnabled.isSelected());
		}
		enableAllCipherFamily(securityEnabled.isSelected());
	    }
	});


	int y = 0;

	GridBagUtil.constrain(this, securityEnabled,
			      0, y, 1, 1, 
			      0.0, 0.0,
			      GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
			      0, 0, 0, 0);
	try {
	    Hashtable args = new Hashtable();
	    args.put("formop", "LIST_TOKEN");
	    args.put("sie", sie==null?consoleInfo.get("SIE"):sie);

	    AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
						  "admin-serv/tasks/configuration/SecurityOp"),
					  consoleInfo.getAuthenticationDN(),
					  consoleInfo.getAuthenticationPassword());

	    admTask.setArguments(args);

	    // respond to password challenge on demand
	    if (SecurityUtil.execWithPwdInput(admTask, args, null) &&
	       (!SecurityUtil.showError(admTask))) {
		Parser tokens = new Parser(admTask.getResultString().toString());
		Hashtable pkcs11TokenInfo = new Hashtable();

		String typeKeyword;
		while (tokens.hasMoreElement()) {
		    typeKeyword = tokens.nextToken();

		    if (typeKeyword.equals("<TOKENLIST>")) {
			pkcs11TokenInfo = tokens.getTokenObject(typeKeyword);
			break;
		    }
		}

		Enumeration keys = pkcs11TokenInfo.keys();
		while (keys.hasMoreElements()) {
		    String familyName = (String)(keys.nextElement());
		    if (familyName.endsWith("_TOKEN")) {

			Hashtable deviceName = (Hashtable)(pkcs11TokenInfo.get(familyName));
			CipherFamilyPane cipherFamilyPane = new CipherFamilyPane(familyName.substring(0, familyName.indexOf("_TOKEN")),deviceName);
			cipherFamilyList.put(familyName.substring(0, familyName.indexOf("_TOKEN")), cipherFamilyPane);
			settings.addElement(cipherFamilyPane);
			GridBagUtil.constrain(
				  this, cipherFamilyPane,
				  0, ++y,  1, 1, 
				  1.0, 0.0,
				  GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
				  0, 0, SuiConstants.COMPONENT_SPACE, 0);
		    } else if (familyName.equals("SECURITY")) {

			//reuse familyName, actually the tokenlist also contain a 
			//"SECURITY" key which indicate if a server is a domestic or
			//export build.
			Object domestic = pkcs11TokenInfo.get("SECURITY");
			_encryptionOptions.setSecurityIsDomestic(((domestic!=null)&&domestic.equals("domestic"))?true:false);
		    }

		    setSaved();
		}
	    }
	} catch (Exception e) {
	    SecurityUtil.printException("EncryptionPanel::EncryptionPanel(...)",e);
	}
    }

    class CipherFamilyPane extends JPanel {
	JCheckBox on;
	JComboBox device;	    
	JComboBox cert;
	String _cipherFamily;

	Hashtable _secDevice;
	JButton cipherButton;

	//initial setting, for reset purpose
	boolean initialOn;
	Object initialDevice;
	Object initialCert;

	public void reset() {
	    Debug.println("Reset:"+(initialOn?"on":"off")+" : "+initialDevice+" : "+initialCert);
	    on.setSelected(initialOn);
	    device.setSelectedItem(initialDevice);
	    cert.setSelectedItem(initialCert);
	}

	public void setEnabled(boolean enabled) {
	    on.setEnabled(enabled);
	    device.setEnabled(enabled);
	    cert.setEnabled(enabled);
	    cipherButton.setEnabled(enabled);
	}

	public void setSaved() {
	    Debug.println("Initialize reset value:"+(initialOn?"on":"off")+" : "+initialDevice+" : "+initialCert);

	    //get initiali setting;
	    initialOn = on.isSelected();
	    initialDevice = device.getSelectedItem();
	    initialCert = cert.getSelectedItem();
	}

	public CipherFamilyPane(String cipherFamily, Hashtable secDevice) {
	    super();
	    setLayout(new GridBagLayout());

	    _cipherFamily = cipherFamily;
	    _secDevice = secDevice;

	    on = new JCheckBox(resource.getString("EncryptionPanel", "enableCipherFamilyLabel")+" "+_cipherFamily);
	    on.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
			if (EncryptionPanel.this.setupComplete) {
			    _encryptionOptions.cipherFamilyEnabledChanged(_cipherFamily, on.isSelected());
			}
		    }
		});
	    on.setSelected(_encryptionOptions.isCipherFamilyEnabled(_cipherFamily));

	    JPanel top = new JPanel();
	    top.setAlignmentX(0.0f);
	    top.setLayout(new BoxLayout(top, BoxLayout.X_AXIS));
	    top.add(on);

	    CompoundBorder cp = new CompoundBorder(
			  new ToggleBorder(top, SwingConstants.TOP),
			  new EmptyBorder(0, SuiConstants.COMPONENT_SPACE,
					  SuiConstants.COMPONENT_SPACE, SuiConstants.COMPONENT_SPACE));

	    setBorder(cp);

	    GridBagUtil.constrain(this, top, 0, 0, 1, 1, 0.0, 0.0,
				  GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
				  0, 0, 0, 0);

	    JPanel content = new JPanel();
	    content.setLayout(new GridBagLayout());

	    JLabel certDeviceLabel = new JLabel(resource.getString("EncryptionPanel", "securityDeviceLabel"), JLabel.LEFT);
	    JLabel certLabel = new JLabel(resource.getString("EncryptionPanel", "certificateLabel"), JLabel.LEFT);
	    JLabel cipherLabel = new JLabel(resource.getString("EncryptionPanel", "cipherLabel"), JLabel.LEFT);


	    cert = new JComboBox();
	    certLabel.setLabelFor(cert);
	    cert.setActionCommand("EVENT_HANDLE_ENABLED");
	    cert.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    Object item = cert.getSelectedItem();
		    if ((EncryptionPanel.this.setupComplete) && e.getActionCommand().equals("EVENT_HANDLE_ENABLED")) {
			_encryptionOptions.selectedCertificateChanged(_cipherFamily, item==null?"":item.toString());
		    }
		}
	    });

	    Enumeration deviceEnum = secDevice.keys();
	    Vector deviceList = new Vector();
	    while (deviceEnum.hasMoreElements()) {
		deviceList.addElement(deviceEnum.nextElement());
	    }
	    device = new JComboBox(deviceList);
	    certDeviceLabel.setLabelFor(device);
	    device.addActionListener(new ActionListener(){
		public void actionPerformed(ActionEvent e) {
		    Object item = device.getSelectedItem();
		    if (EncryptionPanel.this.setupComplete) {
			_encryptionOptions.selectedDeviceChanged(_cipherFamily, item==null?"":item.toString());
		    }
		    try {
			//disable cert list combobox so it won't generate any event
			cert.setActionCommand("EVENT_HANDLE_DISABLED");
			cert.removeAllItems();
			Hashtable selectedDev = (Hashtable)(_secDevice.get((String)(device.getSelectedItem())));
			Enumeration device_enum = selectedDev.keys();
			DefaultComboBoxModel comboModel = (DefaultComboBoxModel) cert.getModel();
			while (device_enum.hasMoreElements()) {
				String key = (String)(device_enum.nextElement());
				if (key.startsWith("CERT")) {
					String certName = (String)selectedDev.get(key);
					// Multiple certs with the same name can exit (bug 558903)
                    // Filter out name duplicates
					if (comboModel.getIndexOf(certName) < 0) {
						cert.addItem(certName);
					}
				}
			}
			cert.validate();
			cert.repaint();
			
			// Try to match a previously configured cert with the current selection
			Object configuredCert = _encryptionOptions.getSelectedCertificate(_cipherFamily);
			cert.setSelectedItem(configuredCert);
			item = cert.getSelectedItem();

			// If a ComboBox item was selected (item != null) and it does
			// not match the configured cert name, the configured cert
			// name might have been stored without the "<device>:" prefix.
			if (item != null && configuredCert != null) {
				if (!item.toString().equals(configuredCert.toString())) {
					Object deviceItem = device.getSelectedItem();
					if (deviceItem != null) {
						cert.setSelectedItem(deviceItem.toString() + ":" + configuredCert);
						item = cert.getSelectedItem();
					}
				}
			}

			if (item == null && cert.getItemCount() > 0) {
				cert.setSelectedIndex(0);
				item = cert.getSelectedItem();
			}
			_encryptionOptions.selectedCertificateChanged(_cipherFamily, item==null?"":item.toString());

		    } catch (Exception nocert) {
		    }
		    finally {
			//enable cert list combobox so it will start generate event
			cert.setActionCommand("EVENT_HANDLE_ENABLED");
		    }
		}
	    });
	    try {
		Object configuredDevice = _encryptionOptions.getSelectedDevice(_cipherFamily);
		device.setSelectedItem(configuredDevice);
		Object item = device.getSelectedItem();
		if (item == null && device.getItemCount() > 0) {
			device.setSelectedIndex(0);
			item = device.getSelectedItem();
		}
		_encryptionOptions.selectedDeviceChanged(_cipherFamily, item==null?"":item.toString());
	    } catch (Exception e) {
	    }

	    cipherButton = new JButton(resource.getString("EncryptionPanel", "settingsLabel"));
	    cipherButton.setToolTipText(resource.getString("EncryptionPanel", "settings_tt"));
	    cipherButton.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    _encryptionOptions.showCipherPreferenceDialog(_cipherFamily);
		}
	    });

	    int y = 1;
	    GridBagUtil.constrain(content, certDeviceLabel,
				  0, y,  1, 1, 
				  0.0, 0.0,
				  GridBagConstraints.EAST, GridBagConstraints.NONE,
				  0, 0, SuiConstants.COMPONENT_SPACE, 0);

	    GridBagUtil.constrain(content, device,
				  1, y,  1, 1, 
				  1.0, 1.0,
				  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
				  0, SuiConstants.COMPONENT_SPACE, SuiConstants.COMPONENT_SPACE, 0);

	    GridBagUtil.constrain(content, certLabel,
				  0, ++y,  1, 1, 
				  0.0, 1.0,
				  GridBagConstraints.EAST, GridBagConstraints.NONE,
				  0, 0, SuiConstants.COMPONENT_SPACE, 0);

	    GridBagUtil.constrain(content, cert,
				  1, y,  1, 1, 
				  1.0, 1.0,
				  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
				  0, SuiConstants.COMPONENT_SPACE, SuiConstants.COMPONENT_SPACE, 0);

	    GridBagUtil.constrain(content, cipherLabel,
				  0, ++y,  1, 1, 
				  0.0, 0.0,
				  GridBagConstraints.EAST, GridBagConstraints.NONE,
				  0, 0, 0, 0);

	    GridBagUtil.constrain(content, cipherButton,
				  1, y,  1, 1, 
				  0.0, 0.0,
				  GridBagConstraints.WEST, GridBagConstraints.NONE,
				  0, SuiConstants.COMPONENT_SPACE, 0, 0);

	    GridBagUtil.constrain(this, content,
				  0, 1,  1, 1, 
				  1.0, 1.0,
				  GridBagConstraints.WEST, GridBagConstraints.BOTH,
				  0, SuiConstants.COMPONENT_SPACE, 0, 0);

	    EncryptionPanel.this.setupComplete = true;
	}
    }

    class ToggleBorder extends EtchedBorder {
        private JComponent _switchPanel;
        private int _switchAlign;

        public ToggleBorder(JComponent sp, int align) {
            _switchPanel = sp;
            _switchAlign = align;
        }

        public void paintBorder(Component c, Graphics g, int x, int y,
                int width, int height) {
            Color save = g.getColor();

            int top = y + (_switchPanel.getHeight() >> 1);
            int new_height = height - top;

            BorderUIResource.getEtchedBorderUIResource().paintBorder(c,
                    g, x, top, width, new_height);
        }
    }
    
    //for testing purpose, to next developer who try to use this
    //make sure to change the admin url and port number for this
    //main program to work correct
    //you might alos need to change the admin uid and password
    /*public static void main(String args[]) {
	try {
            UIManager.setLookAndFeel(new SuiLookAndFeel());
        } catch (Exception e) {}
	Debug.setTrace(true);


        JFrame f = new JFrame();
        ConsoleInfo consoleInfo = new ConsoleInfo();
        consoleInfo.setAuthenticationDN("admin");
        consoleInfo.setAuthenticationPassword("admin");
        consoleInfo.setAdminURL("http://buddha:8081/");
        //consoleInfo.setAdminURL("http://awing:5000/");
	consoleInfo.setPort(8081);
	//consoleInfo.setPort(5000);
	consoleInfo.setHost("buddha");

        try {
            AdmTask task = new AdmTask(
                    new URL(consoleInfo.getAdminURL() + 
			    "admin-serv/tasks/configuration/SSLActivate"),
		    //"admin-serv/tasks/configuration/SecurityOp"),
                    consoleInfo.getAuthenticationDN(),
                    consoleInfo.getAuthenticationPassword());

	    Hashtable arg = new Hashtable();
	    arg.put("security", "off");
	    arg.put("familyList", "RSA,");
	    arg.put("RSA-activated", "on");
	    arg.put("RSA-token", "internal (software)");
	    arg.put("RSA-cert", "Server-Cert");
            arg.put("trustdb" , "admin-serv-buddha");
	    arg.put("ssl2-activated", "on");
	    arg.put("ssl2", "+desede3,+des,+rc2,+rc4,+rc2export,+rc4export");
	    arg.put("ssl3-activated", "on");
	    arg.put("ssl3", "-rsa_null_md5,-fortezza_null,+fortezza_rc4_128_sha,+fortezza,-rsa_fips_3des_sha,-rsa_fips_des_sha,+rsa_3des_sha,+rsa_rc4_128_md5,+rsa_des_sha,+rsa_rc2_40_md5,+rsa_rc4_40_md5");

	    task.setArguments(arg);
            task.exec();
            //System.out.println(task.getStatus());
            //if (task.getStatus()) {  do some error message here }
            System.out.println(task.getResultString().toString());
        }
        catch (Exception e) {}

        EncryptionPanel ep = new EncryptionPanel(consoleInfo, "admin-serv-buddha") {
	    public void securityEnabledChanged(boolean enabled) {}
	    public void cipherFamilyEnabledChanged(String cipherFamily, boolean enabled) {}
	    public void selectedDeviceChanged(String cipherFamily, String device) {}
	    public void selectedCertificateChanged(String cipherFamily, String certName) {}
	    public void showCipherPreferenceDialog(String cipherFamily) {}
	    public boolean isSecurityEnabled() { return true;}
	    public String getSelectedDevice(String cipherFamily) { System.out.println("select device"+cipherFamily);return "";}
	    public String getSelectedCertificate(String cipherFamily) {System.out.println("select cert"+cipherFamily);return "";}
	    public boolean isCipherFamilyEnabled(String cipherFamily) {return false;}
	};
	JDialog d = new JDialog(f, "test", true);

	d.getContentPane().add(ep);
                                                    
        d.setSize(640,480);

        d.show();
	System.exit(0);
    }*/

}
