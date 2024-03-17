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

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellEditor;

import com.netscape.management.client.components.Table;
import com.netscape.management.client.util.AbstractDialog;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.Help;
import com.netscape.management.client.util.ResourceSet;

/**
 * Cipher preference dialog
 *
 * The cipher preference dialog allows user to 
 * enable/disable ciphers. 
 * This is only the UI portion of the setting,
 * so it's up to individual application to
 * determine how cipher setting are stored.
 *
 */
public class CipherPreferenceDialog extends AbstractDialog {

    Vector _ciphers;
    Hashtable _cipherSettings = new Hashtable();
    Table cipherTable;

    JTabbedPane tabbedPane;

    Help help; 

    /*property string */
    String aes, rc2, rc4, des, tripleDes, fips, none, v2, v3, tls, export, enabledTitle;
    String aesGcm, cipherAll;
    String sha, md5, fortezza, cipherLabel, bits, msgAlgo, version, title;


    /* ssl v2 */
    public final static String SSL_V2  = "V2";
    /* ssl v3 */
    public final static String SSL_V3  = "V3";
    /* ssl tls */
    public final static String SSL_TLS = "TLS";


    // export ssl2 cipher
    /**SSL2 Export - RC4 with 40 bit encryption and MD5 message authentication*/
    public final static String RC4EXPORT = "rc4export";
    /**SSL2 Export - RC2 with 40 bit encryption and MD5 message authentication*/
    public final static String RC2EXPORT = "rc2export";

    // domestic ssl2 cipher
    /**SSL2 Domestic - RC4 with 128 bit encryption and MD5 message authentication*/
    public final static String RC4  = "rc4";
    /**SSL2 Domestic - RC2 with 128 bit encryption and MD5 message authentication*/
    public final static String RC2  = "rc2";
    /**SSL2 Domestic - DES with 56 bit encryption and MD5 message authentication*/
    public final static String DES  = "des";
    /**SSL2 Domestic - Triple DES with 168 bit encryption and MD5 message authentication*/
    public final static String DES3 = "desede3";

    // export ssl3 cipher
    /**SSL3 Export - RC4 with 40 bit encryption and MD5 message authentication*/
    public final static String RSA_RC4_40_MD5  = "rsa_rc4_40_md5";
    /**SSL3 Export - RC2 with 40 bit encryption and MD5 message authentication*/
    public final static String RSA_RC2_40_MD5  = "rsa_rc2_40_md5";
    /**SSL3 Export - No encryption, only MD5 message authentication*/
    public final static String RSA_NULL_MD5    = "rsa_null_md5";
    /**SSL3 Export - No encryption, only SHA message authentication*/
    public final static String RSA_NULL_SHA    = "rsa_null_sha";

    /**TLS Export - TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    public final static String TLS_RSA_DES_SHA_AUX = "tls_rsa_export1024_with_des_cbc_sha";
    public final static String TLS_RSA_DES_SHA = "rsa_des_56_sha";
    /**TLS Export - TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    public final static String TLS_RSA_RC4_SHA_AUX = "tls_rsa_export1024_with_rc4_56_sha";
    public final static String TLS_RSA_RC4_SHA = "rsa_rc4_56_sha";
    /**TLS - TLS_RSA_WITH_AES_128_CBC_SHA */
    public final static String TLS_RSA_WITH_AES_128_CBC_SHA_AUX = "tls_rsa_aes_128_sha";
    public final static String TLS_RSA_WITH_AES_128_CBC_SHA = "rsa_aes_128_sha";
    /**TLS - TLS_RSA_WITH_AES_256_CBC_SHA */
    public final static String TLS_RSA_WITH_AES_256_CBC_SHA_AUX = "tls_rsa_aes_256_sha";
    public final static String TLS_RSA_WITH_AES_256_CBC_SHA = "rsa_aes_256_sha";

    /**TLS - TLS_RSA_WITH_AES_128_GCM_SHA256 */
    public final static String TLS_RSA_WITH_AES_128_GCM_SHA256 = "TLS_RSA_WITH_AES_128_GCM_SHA256";
    public final static String CIPHERALL = "all";

    // domestic ssl3 cipher
    /**SSL3 Domestic - DES with 56 bit encryption and SHA message authentication*/
    public final static String RSA_DES_SHA     = "rsa_des_sha";
    /**SSL3 Domestic - RC4 with 128 bit encryption and MD5 message authentication*/
    public final static String RSA_RC4_128_MD5 = "rsa_rc4_128_md5";
    /**SSL3 Domestic - Triple DES with 168 bit encryption and SHA message authentication*/
    public final static String RSA_3DES_SHA    = "rsa_3des_sha";
    /**SSL3 Domestic - RC4 with 128 bit encryption and SHA message authentication*/
    public final static String RSA_RC4_128_SHA = "rsa_rc4_128_sha";

    // fortezza ciphers
    /**SSL3 Domestic - Fortezza with 80 bit encryption and SHA message authentication */
    public final static String FORTEZZA             = "fortezza";
    /**SSL3 Domestic - RC4 with 128 bit encryption and Fortezza/SHA message authentication */
    public final static String FORTEZZA_RC4_128_SHA = "fortezza_rc4_128_sha";
    /**SSL3 Domestic - No encryption, only Fortezza and SHA message authentication */
    public final static String FORTEZZA_NULL        = "fortezza_null";

    // FIPS ciphers
    public final static String RSA_FIPS_DES_SHA_AUX  = "rsa_fips_des_sha";
    public final static String RSA_FIPS_DES_SHA  = "fips_des_sha";
    public final static String RSA_FIPS_3DES_SHA_AUX = "rsa_fips_3des_sha";
    public final static String RSA_FIPS_3DES_SHA = "fips_3des_sha";

    /* default SSL V2 export ciphers */
    final static String V2EXPORT   = "-"+RC2EXPORT+
                                  ",-"+RC4EXPORT;

    /* default SSL V2 domestic ciphers */
    final static String V2DOMESTIC = "-"+RC2+
                                  ",-"+RC4+
                                  ",-"+DES+
                                  ",-"+DES3;
    
    /* default SSL V3 domestic ciphers */
    final static String V3EXPORT   = "-"+RSA_NULL_MD5+
                                  ",-"+RSA_NULL_SHA+
                                  ",+"+RSA_RC4_40_MD5+
                                  ",+"+RSA_RC2_40_MD5;

    /* default SSL V3 domestic ciphers */
    final static String V3DOMESTIC = "+"+RSA_RC4_128_MD5+
                                  ",+"+RSA_DES_SHA+
                                  ",+"+RSA_FIPS_DES_SHA+
                                  ",+"+RSA_3DES_SHA+
                                  ",+"+RSA_FIPS_3DES_SHA;

    final static String V3DOMESTIC_AUX = "+"+RSA_RC4_128_MD5+
                                  ",+"+RSA_DES_SHA+
                                  ",+"+RSA_FIPS_DES_SHA_AUX+
                                  ",+"+RSA_3DES_SHA+
                                  ",+"+RSA_FIPS_3DES_SHA_AUX;

    /* default SSL V3 domestic fortezza ciphers */
    final static String V3FORETEZZA = "-"+FORTEZZA+
                                  ",-"+FORTEZZA_RC4_128_SHA+
                                  ",-"+FORTEZZA_NULL;

    /* default SSL V3 domestic tls ciphers */
    final static String V3TLS = "+"+TLS_RSA_RC4_SHA+
                                ",+"+TLS_RSA_DES_SHA+
                                ",+"+TLS_RSA_WITH_AES_128_CBC_SHA+
                                ",+"+TLS_RSA_WITH_AES_256_CBC_SHA;

    final static String V3TLS_AUX = "+"+TLS_RSA_RC4_SHA_AUX+
                                ",+"+TLS_RSA_DES_SHA_AUX+
                                ",+"+TLS_RSA_WITH_AES_128_CBC_SHA_AUX+
                                ",+"+TLS_RSA_WITH_AES_256_CBC_SHA_AUX;

    class cipherListModel extends AbstractTableModel {
	Vector _header;
	Vector _rowData;
	JLabel label = new JLabel();

	public Class getColumnClass(int c) {
	    return getValueAt(0, c).getClass();
	}

	public boolean isCellEditable(int row, int col) {
	    return (getValueAt(row, col) instanceof Boolean);
	}


	public TableCellEditor getColumnCellEditor(int col) {
	    if (col == 0) {
		JCheckBox checkBox = new JCheckBox();

		return new DefaultCellEditor(checkBox);
	    }

	    return new DefaultCellEditor(new JTextField());
	}


	//Vector _tableModelListener;
	public cipherListModel(Vector columnIdentifier, Vector rowData) {
	    this._header = columnIdentifier;
	    this._rowData = rowData;
	}

	public void setRowData(Vector rowData) {
	    _rowData = rowData;
	}

	public int getRowCount() {
	    return _rowData.size();
	}

	public int getColumnCount() {
	    return _header.size();
	}

	public String getColumnName(int columnIndex) {
	    return (columnIndex >= _header.size() ? "":
		    (String)(_header.elementAt(columnIndex)));
	}

	public Object getValueAt(int rowIndex, int columnIndex) {
	    return ((CipherEntry)(_rowData.elementAt(rowIndex))).getObject(getColumnName(columnIndex));
	}

        /*
         * Don't need to implement this method unless your table's
         * data can change.
         */
        public void setValueAt(Object value, int row, int col) {
	    try {
		((CipherEntry)(_rowData.elementAt(row))).setSelected(((Boolean)value).booleanValue());
	    } catch (Exception e) {
		//we only allow enable/disable of the ciphers, so if
		//this editable value is not boolean (on/off) then we
		//shouldn't even allow user to modify the field.
		//	public boolean isCellEditable(int row, int col); (see above)
		//determine if a cell is editable
	    }
        }
    }

    class CipherEntry {
	public String _cipher;
	public JCheckBox _enabled;
	public String _cipherLabel;
	public int _bits;
	public String _messageAlgo;
	public String _sslVersion;
	public boolean _export;
	public CipherEntry(String cipher, 
	boolean enabled, 
	String cipherLabel,
	int bits,
	String messageAlgo,
	String sslVersion) {
	    this(cipher, enabled, cipherLabel, bits, messageAlgo, sslVersion, false);
	}

	public CipherEntry(String cipher, 
		boolean enabled, 
		String cipherLabel,
		int bits,
		String messageAlgo,
		String sslVersion,
		boolean export) {
	    this._cipher = cipher;
	    this._enabled = new JCheckBox("", enabled);
	    this._cipherLabel = cipherLabel;
	    this._bits = bits;
	    this._messageAlgo = messageAlgo;
	    this._sslVersion = sslVersion;
	    this._export = export;
	    _cipherSettings.put(cipher, this);
	    //_enabled.addActionListener(this);
	}

	public void setSelected(boolean selected) {
	    CipherPreferenceDialog.this.cipherStateChanged(_sslVersion, _cipher, selected);
	    _enabled.setSelected(selected);
	}

	public Object getObject(String columnIndex) {
	    //use table column label as a way to index the cipher data.
	    if (columnIndex.equals(cipherLabel)) {
		return _cipherLabel + (_export?(" "+export):(""));
	    } else if (columnIndex.equals(bits)) {
		return _bits==0?none:Integer.toString(_bits);
	    } else if (columnIndex.equals(msgAlgo)) {
		return _messageAlgo;
	    } else if (columnIndex.equals(version)) {
		if (_sslVersion.equals(SSL_V2)) {
		    return v2;
		} else if (_sslVersion.equals(SSL_V3)) {
		    return v3;
		} else {
		    return "";
		}
		//return "SSL "+Float.toString(_sslVersion);
	    } else {
		return _enabled.isSelected()?Boolean.TRUE:Boolean.FALSE;
	    }
	}

    }

    /**
     * This get called when ever cipher changes state from on->off or
     * off->on.  Overload this function to catch the event
     *
     * Example:
     *    if RC4EXPORT was disabled, this function will be called
     *      with the following parameters:  cipherStateChange(SSL_V2, RC4EXPORT, false);
     *
     * @param SSLVersion ssl version, SSL_V2, SSL_V2, or SSL_TLS 
     * @param cipher the cipher that got enabled/disabled
     * @param enabled true if cipher is enabled, false otherwise.
     */
    public void cipherStateChanged(String SSLVersion, String cipher, boolean enabled) {
	Debug.println("cipher: "+cipher+" change state to: "+enabled);
	//System.out.println("cipher: "+cipher+" change state to: "+enabled);
    }

    /**
     * This get called when ever a SSL version on/off event occures.
     * Overload this function to catch the event
     *
     * @param SSLVersion ssl version, SSL_V2, SSL_V3, SSL_TSL
     * @param enabled true if enabled false otherwise.
     *
     */
    /*public void sslVersionStateChange(String SSLVersion, boolean enabled) {
	Debug.println("sslVersion: "+SSLVersion+" change state to: "+enabled);
    }*/


    /**
     * Called when HELP button is pressed
     */
    protected void helpInvoked() {
	String selectedTabTitle = tabbedPane.getTitleAt(tabbedPane.getSelectedIndex());

	if (selectedTabTitle.equals(v3)) {
	    help.contextHelp("CipherPreferenceDialog", "v3Help");
	} else if (selectedTabTitle.equals(tls)) {
	    help.contextHelp("CipherPreferenceDialog", "tlsHelp");
	} else {
	    help.contextHelp("CipherPreferenceDialog", "v2Help");
	}
    }

    /* setup localized string */
    void init() {
	ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

	help = new Help(resource);

	aes           = resource.getString("CipherPreferenceDialog", "aes");
	rc2           = resource.getString("CipherPreferenceDialog", "rc2");
	rc4           = resource.getString("CipherPreferenceDialog", "rc4");
	des           = resource.getString("CipherPreferenceDialog", "des");
	tripleDes     = resource.getString("CipherPreferenceDialog", "3des");
	fips          = resource.getString("CipherPreferenceDialog", "fips");
	export        = resource.getString("CipherPreferenceDialog", "export");
	none          = resource.getString("CipherPreferenceDialog", "none");
	md5           = resource.getString("CipherPreferenceDialog", "md5");
	sha           = resource.getString("CipherPreferenceDialog", "sha");
	fortezza      = resource.getString("CipherPreferenceDialog", "fortezza");
	v2            = resource.getString("CipherPreferenceDialog", "v2");
	v3            = resource.getString("CipherPreferenceDialog", "v3");
	tls           = resource.getString("CipherPreferenceDialog", "tls");
	cipherLabel   = resource.getString("CipherPreferenceDialog", "cipherLabel");
	bits          = resource.getString("CipherPreferenceDialog", "bits");
	msgAlgo       = resource.getString("CipherPreferenceDialog", "msgAlgo");
	version       = resource.getString("CipherPreferenceDialog", "sslV");
	title         = resource.getString("CipherPreferenceDialog", "title");
	enabledTitle  = resource.getString("CipherPreferenceDialog", "enabledTitle");

	aesGcm        = resource.getString("CipherPreferenceDialog", "aesgcm");
	cipherAll     = resource.getString("CipherPreferenceDialog", "all");
    }

    /**
     * Get a list of ciphers that are currently been displayed.
     * 
     * @return cipher list that is currently been displayed in the dialog
     */
    public Vector getCipherList(String SSLVersion){
	Vector ciphers = new Vector();

	Enumeration keys = _cipherSettings.keys();
	while (keys.hasMoreElements()) {
	    String key = (String)(keys.nextElement());

	    if (key.startsWith(SSLVersion)) {
		ciphers.addElement(((CipherEntry)(_cipherSettings.get(key)))._cipher);
	    }
	}

	return ciphers;
    }


    /**
     * Get cipher preference in a string representation.  The string
     * can be saved, then passed into the cipher preference dialog
     * constructor as an initialization cipher list.
     *
     * For example RC2, and RC4 is displayed on the dialog, further more
     * assume RC2 is enabled, and RC4 is disabled.  This api will return
     *      "+"RC2+",-"+RC4 -> "+rc2,+rc4"
     *
     *
     * @param SSLVersion ssl version, SSL_V2, SSL_V2, or SSL_TLS 
     * @return comma delimited +|-CIPHERNAME string
     *
     */
    public String getCipherPreference(String SSLVersion) {
	StringBuffer cipherList = new StringBuffer();

	Enumeration keys = _cipherSettings.keys();
	while (keys.hasMoreElements()) {
	    String key = (String)(keys.nextElement());
	    
	    if (key.startsWith(SSLVersion)) {
		CipherEntry cipher = (CipherEntry)(_cipherSettings.get(key));
		cipherList.append(cipherList.length()>0?",":"");
		cipherList.append(cipher._enabled.isSelected()?"+":"-");
		cipherList.append(cipher._cipher);
	    }
	}

	return cipherList.toString();
    }


    /**
     * Determain if specified cipher is enabled.
     *
     * @param SSLVersion ssl version, SSL_V2, SSL_V2, or SSL_TLS 
     * @return true is cipher is enabled, false otherwise.
     *
     */
    public boolean isCipherEnabled(String SSLVersion, String cipher) {
	Object cipherEntry = _cipherSettings.get(SSLVersion+cipher);
	boolean enabled = false;

	if (cipherEntry != null) {
	    enabled = ((CipherEntry)cipherEntry)._enabled.isSelected();
	}

	return enabled;
    }

    /**
     * Determain if specific ssl version is enabled or disabled.
     * 
     * @param SSLVersion ssl version, SSL_V2, SSL_V2, or SSL_TLS 
     * @return true if at least one cipher under that SSLVersion is enabled, false if all of them are disabled.
     *
     */
    public boolean isSSLVersionEnabled(String SSLVersion) {
	boolean enabled = false;

	Enumeration keys = _cipherSettings.keys();
	while (keys.hasMoreElements()) {
	    String key = (String)(keys.nextElement());
	    
	    if (key.startsWith(SSLVersion)) {
		CipherEntry cipher = (CipherEntry)(_cipherSettings.get(key));
		if (cipher._enabled.isSelected()) {
		    enabled = true;
		    break;
		}
	    }
	}

	return enabled;
    }


    /**
     * Enable (or disable) the cipher
     *
     * @param SSLVersion ssl version, SSL_V2, SSL_V2, or SSL_TLS 
     * @param cipher string representation of the cipher
     * @param enabled true to enable a cipher
     */
    public void setCipherEnabled(String SSLVersion, String cipher, boolean enabled) {
	Object cipherEntry = _cipherSettings.get(SSLVersion+cipher);

	if (cipherEntry != null) {
	    ((CipherEntry)cipherEntry)._enabled.setSelected(enabled);
	}
	
	cipherTable.validate();
	cipherTable.repaint();
    }


    /**
     *  Enable/disable a list of ciphers, that comma delimited
     *  concatenate '+' to the front of the cipher string to enable a cipher.
     *  a '-' on the othe rhand disable the cipher
     *  for example:  "+"+RC4+",-"+RC2 will 
     *                enable 
     *                   "RC4 with 128 bit encryption and MD5 message authentication"
     *                disable
     *                    RC2 with 128 bit encryption and MD5 message authentication
     *
     *  @param cipherList list of cipher to enable/disable
     */
    public void setCipherEnabled(String SSLVersion, String cipherList) {
	StringTokenizer st = new StringTokenizer(cipherList, ",", false);
	while (st.hasMoreTokens()) {
	    String cipher = st.nextToken();
	    boolean enabled = cipher.startsWith("+");
	    setCipherEnabled(SSLVersion, cipher.substring(1, cipher.length()), enabled);
	}
    }

    /**
     * Enable (or disable) ssl version
     *
     * @param SSLVersion ssl version, SSL_V2, SSL_V2, or SSL_TLS 
     * @param enabled true to enable a cipher
     */
    /*public void setSSLVersionEnabled(String SSLVersion, boolean enabled) {
	Object o = _cipherSettings.get("SSLVersion"+SSLVersion);

	if (o!=null) {
	    ((JCheckBox)(o)).setSelected(enabled);
	}
    }*/


    CipherEntry createCipherEntry(String SSLVersion, String cipher) {
	CipherEntry cipherEntry = null;

	//V2 Cipher
	if (SSLVersion.equals(SSL_V2)) {
	    if (cipher.equals(RC4)) {
		cipherEntry = new CipherEntry(cipher, true, rc4, 128, md5, SSL_V2);
	    } else if (cipher.equals(RC4EXPORT)) {
		cipherEntry = new CipherEntry(cipher, true, rc4, 40, md5, SSL_V2, true);
	    } else if (cipher.equals(RC2)) {
		cipherEntry = new CipherEntry(cipher, true, rc2, 128, md5, SSL_V2);
	    } else if (cipher.equals(RC2EXPORT)) {
		cipherEntry = new CipherEntry(cipher, true, rc2, 40, md5, SSL_V2, true);
	    } else if (cipher.equals(DES)) {
		cipherEntry = new CipherEntry(cipher, true, des, 56, md5, SSL_V2);
	    } else if (cipher.equals(DES3)) {
		cipherEntry = new CipherEntry(cipher, true, des, 168, md5, SSL_V2);
	    } else {
	    	Debug.println("CipherPreferenceDialog.createCipherEntry(): " +
	    				  "Unknown SSLv2 cipher: " + cipher);
	    }

	//V3 Cipher
	} else if (SSLVersion.equals(SSL_V3)) {
	    if (cipher.equals(RSA_RC4_128_MD5)) {
		cipherEntry = new CipherEntry(cipher, true, rc4, 128, md5, SSL_V3);
	    } else if (cipher.equals(RSA_3DES_SHA)) {
		cipherEntry = new CipherEntry(cipher, true, tripleDes, 168, sha, SSL_V3);
	    } else if (cipher.equals(RSA_DES_SHA)) {
		cipherEntry = new CipherEntry(cipher, true, des, 56, sha, SSL_V3);
	    } else if (cipher.equals(RSA_RC4_40_MD5)) {
		cipherEntry = new CipherEntry(cipher, true, rc4, 40, md5, SSL_V3, true);
	    } else if (cipher.equals(RSA_RC2_40_MD5)) {
		cipherEntry = new CipherEntry(cipher, true, rc2, 40, md5, SSL_V3, true);
	    } else if (cipher.equals(RSA_NULL_MD5)) {
		cipherEntry = new CipherEntry(cipher, false, none, 0, md5, SSL_V3);
	    } else if (cipher.equals(RSA_NULL_SHA)) {
		cipherEntry = new CipherEntry(cipher, false, none, 0, sha, SSL_V3);
	    } else if (cipher.equals(RSA_FIPS_DES_SHA)) {
		cipherEntry = new CipherEntry(cipher, true, des+" "+fips, 56, sha, SSL_V3);
	    } else if (cipher.equals(RSA_FIPS_DES_SHA_AUX)) {
		cipherEntry = new CipherEntry(cipher, true, des+" "+fips, 56, sha, SSL_V3);
	    } else if (cipher.equals(RSA_FIPS_3DES_SHA)) {
		cipherEntry = new CipherEntry(cipher, true, tripleDes+" "+fips, 168, sha, SSL_V3);
	    } else if (cipher.equals(RSA_FIPS_3DES_SHA_AUX)) {
		cipherEntry = new CipherEntry(cipher, true, tripleDes+" "+fips, 168, sha, SSL_V3);
		
	    //Fortezza ciphers
	    } else if ( cipher.equals(FORTEZZA)) {
		cipherEntry = new CipherEntry(cipher, true, fortezza, 80, sha, SSL_V3);
	    } else if (cipher.equals(FORTEZZA_RC4_128_SHA)) {
		cipherEntry = new CipherEntry(cipher, true, rc4+" "+fortezza, 128, sha, SSL_V3);
	    } else if (cipher.equals(FORTEZZA_NULL)) {
		cipherEntry = new CipherEntry(cipher, false, none+" "+fortezza, 0, sha, SSL_V3);
	    } else {
	    	Debug.println("CipherPreferenceDialog.createCipherEntry(): " +
	    				  "Unknown SSLv3 cipher: " + cipher);
	    }

	    //TLS Cipher
	} else if (SSLVersion.equals(SSL_TLS)) {
		if (cipher.equals(TLS_RSA_DES_SHA)) {
		    cipherEntry = new CipherEntry(cipher, true, des, 56, sha, SSL_V3, true);
		} else if (cipher.equals(TLS_RSA_DES_SHA_AUX)) {
		    cipherEntry = new CipherEntry(cipher, true, des, 56, sha, SSL_V3, true);
		} else if (cipher.equals(TLS_RSA_RC4_SHA)) {
		    cipherEntry = new CipherEntry(cipher, true, rc4, 56, sha, SSL_V3, true);
		} else if (cipher.equals(TLS_RSA_RC4_SHA_AUX)) {
		    cipherEntry = new CipherEntry(cipher, true, rc4, 56, sha, SSL_V3, true);
		} else if (cipher.equals(TLS_RSA_WITH_AES_128_CBC_SHA)) {
		    cipherEntry = new CipherEntry(cipher, true, aes, 128, sha, SSL_V3, false);
		} else if (cipher.equals(TLS_RSA_WITH_AES_128_CBC_SHA_AUX)) {
		    cipherEntry = new CipherEntry(cipher, true, aes, 128, sha, SSL_V3, false);
		} else if (cipher.equals(TLS_RSA_WITH_AES_256_CBC_SHA)) {
		    cipherEntry = new CipherEntry(cipher, true, aes, 256, sha, SSL_V3, false);
		} else if (cipher.equals(TLS_RSA_WITH_AES_256_CBC_SHA_AUX)) {
		    cipherEntry = new CipherEntry(cipher, true, aes, 256, sha, SSL_V3, false);
		} else if (cipher.equals(TLS_RSA_WITH_AES_128_GCM_SHA256)) {
		    cipherEntry = new CipherEntry(cipher, true, aesGcm, 128, sha, SSL_V3, false);
		} else if (cipher.equals(CIPHERALL)) {
		    cipherEntry = new CipherEntry(cipher, true, cipherAll, 128, sha, SSL_V3, false);
		} else {
		    Debug.println("CipherPreferenceDialog.createCipherEntry(): " +
		    "Unknown TLSv1 cipher: " + cipher);
		}
	}

	if (cipherEntry != null) {
	    _cipherSettings.put(SSLVersion+cipher, cipherEntry);
	}

	return cipherEntry;
    }

    class SSLCipherPref extends JPanel{
	JCheckBox cipherEnabled;

	public SSLCipherPref(String SSLVersion, String sslCipherList) {
	    super();
	    setLayout(new GridBagLayout());
	    Vector ciphers = new Vector();
	    StringTokenizer st = new StringTokenizer(sslCipherList, ",", false);
	    while (st.hasMoreTokens()) {
		String token = st.nextToken();
		try {
		    CipherEntry cipherEntry = createCipherEntry(SSLVersion, token.substring(((token.startsWith("+") || token.startsWith("-"))?1:0), token.length()));
		    if (cipherEntry != null) {
			cipherEntry._enabled.setSelected(token.startsWith("+"));
			ciphers.addElement(cipherEntry);
		    }
		} catch (Exception e) {
		    SecurityUtil.printException("CipherPreferenceDialog::SSLCipherPref::SSLCipherPref(...)",e);
		}
		
	    }

	    Vector _header = new Vector();
	    _header.addElement(enabledTitle);
	    _header.addElement(cipherLabel);
	    _header.addElement(bits);
	    _header.addElement(msgAlgo);
	    //eader.addElement(version);

	    cipherListModel clm = new cipherListModel(_header, ciphers);

	    cipherTable = new Table(clm, true);
	    


	    //JScrollPane scrollPane = new JScrollPane(cipherTable);
	    //cipherTable.setRowSelectionAllowed(false);
	    //cipherTable.setCellSelectionEnabled(false);

	    String sslVersion = "";
	    if (SSLVersion.equals(SSL_V2)) {
		sslVersion = v2;
	    } else if (SSLVersion.equals(SSL_V3)) {
		sslVersion = v3;
	    } else if (SSLVersion.equals(SSL_TLS)) {
		sslVersion = tls;
	    }
	    
	    /*cipherEnabled =  new JCheckBox(sslVersion, true);
	    cipherEnabled.setActionCommand(SSLVersion);
	    _cipherSettings.put("SSLVersion"+SSLVersion, cipherEnabled);
	    cipherEnabled.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    CipherPreferenceDialog.this.sslVersionStateChange(e.getActionCommand(), ((JCheckBox)(e.getSource())).isSelected());
		}
	    });
	    

	    GridBagUtil.constrain(this, cipherEnabled,
				  0, 0, 1, 1,
				  1.0, 0.0,
				  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
				  0, COMPONENT_SPACE, 0, 0);*/
	    cipherTable.size();
	    GridBagUtil.constrain(this, new JScrollPane(cipherTable)/*cipherTable*//*scrollPane*/,
				  0, 0, 1, 1,
				  1.0, 1.0,
				  GridBagConstraints.WEST, GridBagConstraints.BOTH,
				  0, 0, 0, 0);
	   
	    cipherTable.setPreferredScrollableViewportSize(new Dimension(350,200));


	    cipherTable.setBorder(BorderFactory.createEmptyBorder(VERT_WINDOW_INSET,
								  HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET));
	    /*cipherTable.setBorder(new CompoundBorder(
                new MatteBorder(DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, getBackground()),
                new BevelBorder(BevelBorder.LOWERED, Color.white,
                getBackground(), Color.black, Color.black)));*/
	}
    }



    /**
     * Construct a cipher preference dialog base on a string representation 
     * of ciphers list with on/off state.
     * For example, given this string:
     *   "-"+RC4+",+"+RC2+"
     *   which will be passed in as SSL2Cipherlist
     * 
     * A cipher preference dialog will show up containing with 1 tab (SSL v2) with 2 cihpers:
     *   RC4 is disabled and RC2 is enabled
     *
     * If on/off setting is not specified:
     *   RC4+","+RC2 then default [+rc4,+rc2] setting will be used.
     *
     * default setting - cipher is enabled, ciphers that does not use encryption (see cipher declearation) is disabled 
     * 
     *
     * @param parent the frame from which the dialog is displayed
     * @param SSL2CipherList which ssl2 cipher to display.  if null or "" then ssl2 cipher tab won't show.
     * @param SSL3CipherList which ssl3 cipher to display.  if null or "" then ssl3 cipher tab won't show.
     * @param TLSCipherList which tls cipher to display.  if null or "" then tls cipher tab won't show.
     *
     */    
    public CipherPreferenceDialog(Frame parent,
				  String SSL2CipherList,
				  String SSL3CipherList,
				  String TLSCipherList) {
	super(parent, "", true, OK|CANCEL|HELP);

	init();

	setTitle(title);

	tabbedPane = new JTabbedPane();

	if ((SSL2CipherList != null) && (SSL2CipherList.length()>0)) {
	    tabbedPane.addTab(v2, new SSLCipherPref(SSL_V2 , SSL2CipherList));
	}

	if ((SSL3CipherList != null) && (SSL3CipherList.length()>0)) {
	    tabbedPane.addTab(v3, new SSLCipherPref(SSL_V3 , SSL3CipherList));
	}

	if ((TLSCipherList != null) && (TLSCipherList.length()>0)) {
	    Debug.println("CipherPreferenceDialog.CipherPreferenceDialog(): " + "TLSCipherList: " + TLSCipherList);
	    tabbedPane.addTab(tls, new SSLCipherPref(SSL_TLS, TLSCipherList));
	}

	getContentPane().add(tabbedPane);
	pack();
    }

    static String getCipherListString(Vector SSLCipherList) {
	if (SSLCipherList == null) {
	    return "";
	}

	StringBuffer sslCiphers = new StringBuffer();

	for (int i=0; i<SSLCipherList.size(); i++) {
	    sslCiphers.append(sslCiphers.length()>0?",":""+
			      SSLCipherList.elementAt(i).toString());
	}

	return sslCiphers.toString();
    }

    /**
     * Construct a cipher preference dialog base on a string representation 
     * of ciphers list with on/off state.
     * For example, given this string:
     *    [-rc4,+rc2] 
     *    which will be passed in as SSL2Cipherlist
     * A cipher preference dialog will show up containing with 1 tab (SSL v2) with 2 cihpers:
     *   RC4 is disabled and RC2 is enabled
     *
     * If on/off (+/-) setting is not specified:
     *   [rc4,rc2] then default [+rc4,+rc2] setting will be used.
     *
     * default setting - cipher is enabled, ciphers that does not use encryption (see cipher declearation) is disabled 
     *
     * @param parent the frame from which the dialog is displayed
     * @param SSL2CipherList which ssl2 cipher to display.  if null or 0 element in vector then ssl2 cipher tab won't show.
     * @param SSL3CipherList which ssl3 cipher to display.  if null or 0 element in vector then ssl3 cipher tab won't show.
     * @param TLSCipherList which tls cipher to display.  if null or 0 element in vector then tls cipher tab won't show.
     *
     */    
    public CipherPreferenceDialog(Frame parent,
				  Vector SSL2CipherList,
				  Vector SSL3CipherList,
				  Vector TLSCipherList) {

	this(parent, 
	     getCipherListString(SSL2CipherList),
	     getCipherListString(SSL3CipherList),
	     getCipherListString(TLSCipherList));
    }
    

    /**
     * Create a default cipher preference dialog.
     *
     * @param parent the frame from which the dialog is displayed
     * @param enableSSLV2 enable SSL v2 cipher
     * @param enableSSLV3 enable SSL v3 cipher
     * @param tls show TLS ciphers.
     * @param isDomestic show domestic ciphers if true
     * @param fortezza show fortezza ciphers.  If isDomestic is false or SSL_V3 is not enabled, then fortezza will not show.
     *
     */
    public CipherPreferenceDialog(Frame parent,
				  boolean enableSSLV2,
				  boolean enableSSLV3,
				  boolean tls,
				  boolean isDomestic,
				  boolean fortezza) {

	this(parent, 
	     (enableSSLV2 ? V2EXPORT+(isDomestic?","+V2DOMESTIC:""):""),
	     (enableSSLV3 ? V3EXPORT+(isDomestic?","+V3DOMESTIC:""):"")+
	     ((enableSSLV3 & isDomestic & fortezza)?","+V3FORETEZZA:""),
	     tls?(V3EXPORT+(isDomestic?","+V3DOMESTIC:"")+","+V3TLS):"");
    }

    /**
     * Create a default cipher preference dialog.
     *
     * @param parent the frame from which the dialog is displayed
     * @param enableSSLV2 enable SSL v2 cipher
     * @param enableSSLV3 enable SSL v3 cipher
     * @param tls show TLS ciphers.
     * @param isDomestic show domestic ciphers if true
     * @param fortezza show fortezza ciphers.  If isDomestic is false or SSL_V3 is not enabled, then fortezza will not show.
     * @param tlsonly does not include SSLV3 ciphers in TLS cipher list if true
     *
     */
    public CipherPreferenceDialog(Frame parent,
				  boolean enableSSLV2,
				  boolean enableSSLV3,
				  boolean tls,
				  boolean isDomestic,
				  boolean fortezza,
				  boolean tlsonly) {

	this(parent, 
	     (enableSSLV2 ? V2EXPORT+(isDomestic?","+V2DOMESTIC:""):""),
	     (enableSSLV3 ? V3EXPORT+(isDomestic?","+V3DOMESTIC:""):"")+
	     ((enableSSLV3 & isDomestic & fortezza)?","+V3FORETEZZA:""),
	     tls?(tlsonly?V3TLS:(V3EXPORT+(isDomestic?","+V3DOMESTIC:"")+","+V3TLS)):"");
    }

    /**
     * Create a default cipher preference dialog.
     *
     * @param parent the frame from which the dialog is displayed
     * @param enableSSLV2 enable SSL v2 cipher
     * @param enableSSLV3 enable SSL v3 cipher
     * @param tls show TLS ciphers.
     * @param isDomestic show domestic ciphers if true
     * @param fortezza show fortezza ciphers.  If isDomestic is false or SSL_V3 is not enabled, then fortezza will not show.
     * @param tlsonly does not include SSLV3 ciphers in TLS cipher list if true
     * @param dsstyle returns DS style cipher names (search _AUX in this file) if true
     *
     */
    public CipherPreferenceDialog(Frame parent,
				  boolean enableSSLV2,
				  boolean enableSSLV3,
				  boolean tls,
				  boolean isDomestic,
				  boolean fortezza,
				  boolean tlsonly,
				  boolean dsstyle) {

	this(parent, 
	     (enableSSLV2 ? V2EXPORT+(isDomestic?","+V2DOMESTIC:""):""),
	     (enableSSLV3 ? V3EXPORT+(isDomestic?","+V3DOMESTIC_AUX:""):"")+
	     ((enableSSLV3 & isDomestic & fortezza)?","+V3FORETEZZA:""),
	     tls?(tlsonly?V3TLS_AUX:(V3EXPORT+(isDomestic?","+V3DOMESTIC_AUX:"")+","+V3TLS_AUX)):"");
    }

    //for testing purpose
    /*public static void main(String args[]) {
        try {
            UIManager.setLookAndFeel(new SuiLookAndFeel());
        } catch (Exception e) {}
	Debug.setTrace(true);

	JFrame f = new JFrame();


	CipherPreferenceDialog cpd = new CipherPreferenceDialog(f, true, true, true, true, true);

	//CipherPreferenceDialog cpd = new CipherPreferenceDialog(f, "-rc4,-rc2,-rsa_fips_3des_sha,+fortezza_null", "", "");

	//Vector v = new Vector();
	//v.addElement("-rc4");
	//v.addElement("-rc2");
	//cpd.setCipherEnabled(SSL_V2, v);
	cpd.setCipherEnabled(SSL_V2, "-rc4,-rc2");
	cpd.setCipherEnabled(SSL_V3, "-rsa_fips_3des_sha,+fortezza_null");

	//cpd.setSSLVersionEnabled(SSL_V2, false);
	//cpd.setEnabled(SSL_V3, "-"+RC4+",-"+RC2+",-"+RSA_FIPS_3DES_SHA+",+"+FORTEZZA_NULL);
	
	cpd.setVisible(true);

	//Vector list = cpd.getCipherList();
	//for (int i = 0; i<list.size(); i++) {
	//    String cipher = (String)(list.elementAt(i));
	//    System.out.println(cipher+":"+cpd.isEnabled(cipher));
	//}

	System.out.println(cpd.getCipherPreference(SSL_V2));
	System.out.println(cpd.getCipherPreference(SSL_V3));
	System.out.println(cpd.getCipherPreference(SSL_TLS));

	System.out.println(cpd.isSSLVersionEnabled(SSL_V2));
	System.out.println(cpd.isSSLVersionEnabled(SSL_V3));
	System.out.println(cpd.isSSLVersionEnabled(SSL_TLS));
	//cpd = new CipherPreferenceDialog(f, cpd.getCipherPreference(SSL_V2));
	//cpd.show();

	
	System.exit(0);
    }*/
}


