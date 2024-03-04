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

package com.netscape.management.client.ug;

import java.util.*;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.KingpinLDAPConnection;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.ResourceSet;

import netscape.ldap.*;
import netscape.ldap.util.*;


/**
 * ResourcePageObservable is a data structure that holds ldap information.
 * It is intended to be used by the IResourceEditorPage (a plugin interface)
 * to temporarily store ldap related information, and share the same data
 * across multiple plugins. Once all modifications have been completed, the
 * information in this observable is committed to the directory.
 *
 * You do not need to create an instance of this observable, it will be
 * created by the ResourceEditor and passed into IResourceEditorPage as a
 * parameter.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 */
public class ResourcePageObservable extends Observable {
    static final String ID_FORMAT_MAIL = "mail";
    static final String ID_FORMAT_NTUSER = "ntuser";
    static final String ID_FORMAT_FIRSTLETTER_LASTNAME = "firstletter_lastname";
    static final String ID_FORMAT_GIVENNAME_FIRSTLETTER = "givenname_firstletter";
    static final String ID_FORMAT_LASTNAME_GIVENNAME = "lastname_givenname";
    static final String ID_FORMAT_GIVENNAME_LASTNAME = "givenname_lastname";
    static final String STRING_UID = "uid";
    static final String STRING_SN = "sn";
    static final String STRING_GIVENNAME = "givenname";

    private ResourceSet _resource;
    public LDAPEntry _entry; //used to create a local copy, upon save() this entry will contian the new copy
    private ConsoleInfo _info; //connection info

    private Hashtable attributes = new Hashtable(); //local copy of the attribute

    private Vector attrAdd = new Vector(); //specify which attribute does not exist and value(s) should be added
    private Vector attrReplace = new Vector(); //specify which attribute already exist and value(s) should be replaced
    private Vector attrDelete = new Vector(); //specify which attribute does exist and value(s) should be removed

    private Vector _objectClassList; //object class needed to create a new user
    //This class also assume all the "REQUIRED" attribute will be added.
    //This mean all the resource page should contain all the required attribute fields, so
    //the data can be enter and be stored into ldap server.
    public boolean _fNewUser;

    public String _sIndexAttribute = "cn";
    public String _sBaseDN;

    static final int NEW_ENTRY_TIMEOUT = 0xff;
    
    /**
    * Constructor
    *
    * @param connectInfo  session information
    * @param sharedEntry  LDAP entry object
    * @param fNewUser_OR_Group  indicates whether this observable is for a new object
    */
    public ResourcePageObservable(ConsoleInfo connectInfo,
            LDAPEntry sharedEntry, boolean fNewUser_OR_Group) {
        super();
        _resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");
        _info = connectInfo;
        _entry = sharedEntry;
        _fNewUser = fNewUser_OR_Group;

        if (_fNewUser || (sharedEntry == null)) {
            return;
        }

        LDAPAttributeSet attrSet = sharedEntry.getAttributeSet();
        String attr = null;
        for (int i = 0; i < attrSet.size(); i++) {
            attr = attrSet.elementAt(i).getName().toLowerCase();
            attributes.put(attr, attrSet.elementAt(i));
        }

        // get the index attribute
        String sDN = _entry.getDN();
        int iIndex = sDN.indexOf('=');
        if (iIndex > 0) {
            _sIndexAttribute = sDN.substring(0, iIndex);
        }
    }


    /**
     * Sets the object classes for this observable.
     *
     * @param objectClassList  vector of object classes
     */
    public void setObjectClass(Vector objectClassList) {
        _objectClassList = objectClassList;
        add("objectclass",_objectClassList);
    }


    /**
     * Synchronizes the objectclass list with the objectclass
     * attribute values that are present in the observable.
     *
     * @param objectClassList  vector of object classes
     */
    public void syncObjectClassList() {
        _objectClassList = get("objectclass");
    }


    /**
     * Gets the LDAPEntry for the specified DN
     *
     * @param DN  the LDAPEntry to retrieve
     * @param newEntry This is a new entry we just added - if we get
     *                 a NO_SUCH_OBJECT (err=32), we assume this server
     *                 is a replica, and we wait for the entry to show
     *                 up
     * @return    the LDAPEntry for the specified DN
     */
    public LDAPEntry getLDAPEntry(String DN, boolean newEntry) {
		LDAPEntry ldapEntry = null;
		int tries = 10;
		LDAPConnection ldapConnection = null;
		boolean needdisconnect = false;
		while (tries >= 0) {
			try {
				if (ldapConnection == null) {
					ldapConnection = _info.getUserLDAPConnection();
				}
				if (ldapConnection == null) {
					ldapConnection = new KingpinLDAPConnection(
							_info.getAuthenticationDN(),
							_info.getAuthenticationPassword());
					needdisconnect = true;
				}
				if (!ldapConnection.isConnected()) {
					ldapConnection.connect(LDAPUtil.LDAP_VERSION,
							_info.getUserHost(), _info.getUserPort(),
							_info.getAuthenticationDN(),
							_info.getAuthenticationPassword());
				}
				ldapEntry = ldapConnection.read(DN);
				break; // read was successful - break out of while loop
			} catch (LDAPException e) {
				if ((e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT)
						&& newEntry) {
					Debug.println(6, "ResourcePageObservable.getLDAPEntry: "
							+ "waiting for entry " + DN);
					try {
						Thread.sleep(1000);
					} catch (InterruptedException e1) {
						Debug.println("ResourcePageObservable.getLDAPEntry: sleep was "
								+ "interrupted: " + e1);
						break;
					}
					tries--;
				} else {
					Debug.println("ResourcePageObservable.getLDAPEntry: could not read entry ["
							+ DN + "] " + "Error: " + e);
					break; // hard error - done with while loop
				}
			}
		}

		if (needdisconnect && (ldapConnection != null)) {
			try {
				ldapConnection.disconnect();
			} catch (LDAPException e) {
				Debug.println("ResourcePageObservable.getLDAPEntry: could not close connection "
						+ "Error: " + e);
			}
		}
		return ldapEntry;
    }


    /**
     * Sets the attribute that makes the object unique.
     *
     * @param sIndex  the unique attribute
     */
    public void setIndexAttribute(String sIndex) {
        _sIndexAttribute = sIndex;
    }


    /**
     * Retrieves the attribute that makes the object unique.
     *
     * @return  the unique attribute
     */
    public String getIndexAttribute() {
        return _sIndexAttribute;
    }


    /**
     * Retrieves the session information object.
     *
     * @return  the session information
     */
    public ConsoleInfo getConsoleInfo() {
        return _info;
    }


    /**
     * Retrieves the distinguished name.
     *
     * @return  the distinguished name
     */
    public String getDN() {
        if (_entry != null) {
            return _entry.getDN();
        } else
            return null;
    }


    /**
     * Retrieves the base DN where this observable object is created.
     *
     * @return  the creation base DN
     */
    public String getCreateBaseDN() {
        return _sBaseDN;
    }


    /**
     * Set the base DN where this observable object is created.
     *
     * @return  the creation base DN
     */
    public void setCreateBaseDN(String baseDN) {
        _sBaseDN = baseDN;
    }


    /**
     * Commits changes to the directory server and returns a new copy of
     * the LDAP entry.
     *
     * @return  the LDAPEntry object that was saved
     * @exception LDAPException
     */
    public LDAPEntry save() throws LDAPException {
        if (_fNewUser) {
            // create new user
            String createBaseDN = getCreateBaseDN();
            if (createBaseDN == null) {
                // An exception will be thrown later when the object is actually saved.
                Debug.println("ResourcePageObservable: cannot save because base DN is null");
            }

            LDAPConnection ldapConnection = _info.getUserLDAPConnection();
            LDAPAttributeSet Attrs = new LDAPAttributeSet();
            String newRDN = "";

            try {
                int iObjectType = 0; // 0 for not user and not group
                // 1 for user
                // 2 for group
                for (int i = 0; i < _objectClassList.size(); i++) {
                    String sObjectClass =
                            (String)(_objectClassList.elementAt(i));
                    //Attrs.add(new LDAPAttribute("objectclass", sObjectClass));
                    if (sObjectClass.toLowerCase().equals("inetorgperson")) {
                        iObjectType = 1;
                    } else if (sObjectClass.toLowerCase().equals("groupofuniquenames")) {
                        iObjectType = 2;
                    }
                }

                // get the unique index attribute
                switch (iObjectType) {
                case 1:
                    {
                        String sAttribute =
                                ResourceEditor.getUserRDNComponent();
                        if ((sAttribute != null) &&
                                (!sAttribute.equals(""))) {
                            _sIndexAttribute = sAttribute;
                        }

                        String oldUID = get(STRING_UID, 0);
                        if ((oldUID == null) || (oldUID.equals(""))) {
                            // setup the uid value
                            sAttribute =
                                    ResourceEditor.getUniqueAttribute();
                            if ((sAttribute != null) &&
                                    (!sAttribute.equals(""))) {
                                String sUID = "";
                                if (sAttribute.toLowerCase().equals(
                                        STRING_UID)) {
                                    // if unique attribute = uid, then do something special
                                    sAttribute =
                                            ResourceEditor.getUserIDFormat();
                                    if (sAttribute.toLowerCase().equals(
                                            ID_FORMAT_NTUSER)) {
                                        sUID = get("ntUserDomainID",0);
                                        int iColon = sUID.indexOf(':');
                                        if (iColon > 0) {
                                            sUID = sUID.substring(
                                                    iColon + 1);
                                        }
                                    } else if ( sAttribute.toLowerCase().
                                            equalsIgnoreCase(
                                            ID_FORMAT_MAIL)) {
                                        sUID = get(ID_FORMAT_MAIL, 0);
                                    } else if ( sAttribute.toLowerCase().
                                            equalsIgnoreCase(
                                            ID_FORMAT_FIRSTLETTER_LASTNAME)) {
                                        String givenName = get(STRING_GIVENNAME, 0);
                                        String sn = get(STRING_SN, 0);
                                        if ((givenName != null) && !givenName.equals("") &&
                                            (sn != null) && (!sn.equals(""))) {
                                            sUID = givenName.substring(0, 1) + sn;
                                        }
                                    } else if ( sAttribute.toLowerCase().
                                            equalsIgnoreCase(
                                            ID_FORMAT_GIVENNAME_FIRSTLETTER)) {
                                        String givenName = get(STRING_GIVENNAME, 0);
                                        String sn = get(STRING_SN, 0);
                                        if ((givenName != null) && !givenName.equals("") &&
                                            (sn != null) && (!sn.equals(""))) {
                                            sUID = givenName + sn.substring(0, 1);
                                        }
                                    } else if ( sAttribute.toLowerCase().
                                            equalsIgnoreCase(
                                            ID_FORMAT_LASTNAME_GIVENNAME)) {
                                        sUID = get(STRING_SN, 0) +
                                                get(STRING_GIVENNAME, 0);
                                    } else {
                                        // default is Givename + Lastname
                                        sUID = get(STRING_GIVENNAME,
                                                0) + get(STRING_SN, 0);
                                    }
                                } else {
                                    sUID = get(sAttribute, 0);
                                }
                                if (sUID == null) {
                                    sUID = "";
                                }
                                replace(STRING_UID, sUID);
                            }
                        }

                        if (LDAPUtil.isVersion4(
                                _info.getUserLDAPConnection()) == false) {
                            String uid = get(STRING_UID, 0);
                            if (uidAlreadyExists(uid)) {
                                throw new LDAPException(
                                        _resource.getString("ResourcePageObservable",
                                        "uidAlreadyExists") + " " +
                                        uid, LDAPException.ENTRY_ALREADY_EXISTS);
                            }
                        }

                        break;
                    }
                case 2:
                    {
                        String sAttribute =
                                ResourceEditor.getGroupRDNComponent();
                        if ((sAttribute != null) &&
                                (!sAttribute.equals(""))) {
                            _sIndexAttribute = sAttribute;
                        }
                        break;
                    }
                }
                if (createBaseDN != null && createBaseDN.equals("")) {
                    newRDN = _sIndexAttribute + "="+
                            get(_sIndexAttribute, 0);
                } else {
                    // If createBaseDN is null, then the save below will fail.
                    newRDN = _sIndexAttribute + "="+
                            get(_sIndexAttribute, 0) + ","+createBaseDN;
                }

                Enumeration keys = attributes.keys();
                while (keys.hasMoreElements()) {
                    String key = (String)(keys.nextElement());
                    Attrs.add((LDAPAttribute)attributes.get(key));
                }

                LDAPEntry newEntry = new LDAPEntry(newRDN, Attrs);
                ldapConnection.add(newEntry);

                _entry = newEntry;

                // Refresh so we get a copy of the entry from the DS.  This ensures
                // that we see any updates that the DS added to the entry.
                refresh(true);
                if (_entry == null) {
                	String[] arg = {newRDN};
                	String msg = _resource.getString("ResourcePageObservable",
                			"couldNotReadNewEntry", arg);
                	throw new LDAPException(msg, ResourcePageObservable.NEW_ENTRY_TIMEOUT);
                }
            }
            catch (LDAPException e) {
                Debug.println(0,
                        "ResourcePageObservable.java:ADD LDAP ENTRY:"+ 
                        e.getLDAPErrorMessage() + " for "+newRDN);
                throw e;
            }
        }
        else if ( (attrAdd.size() + attrReplace.size() +
                attrDelete.size()) > 0) {
            LDAPModificationSet modificationSet = new LDAPModificationSet();

            for (int i = 0; i < attrDelete.size(); i++) {
                AttributeValuePair attr =
                        (AttributeValuePair)(attrDelete.elementAt(i));
				LDAPAttribute deleteAttribute=new LDAPAttribute(attr.getLDAPAttribute().getName());
                Debug.println("ResourcePageObservable.save: mod.del=" + deleteAttribute);

                // Don't do this mod if the attribute is the index attribute.  Later, we do a rename
                // which makes the attribute go away.  If we add the mod, the modifications will
                // fail throwing an LDAPException.
                if (deleteAttribute != null && !_sIndexAttribute.equals(deleteAttribute.getName())) {
                    modificationSet.add(LDAPModification.DELETE,
                                        deleteAttribute);
                }
            }

            for (int i = 0; i < attrAdd.size(); i++) {
                AttributeValuePair attr =
                    (AttributeValuePair)(attrAdd.elementAt(i));
                if (Debug.isEnabled()) {
                    Debug.println("ResourcePageObservable.save: mod.add=" + attr.getLDAPAttribute());
                }
                modificationSet.add(LDAPModification.ADD,
                                    attr.getLDAPAttribute());
            }
            
            for (int i = 0; i < attrReplace.size(); i++) {
                String attr = (String)(attrReplace.elementAt(i));
                attr = attr.toLowerCase();
                LDAPAttribute ldapAttribute = null;
                if (_entry.getAttribute(attr) == null) {
                    LDAPAttribute attribute =
                            (LDAPAttribute) attributes.get(attr);
                    if (attribute != null) {
                        if (Debug.isEnabled()) {
                            Debug.println("ResourcePageObservable.save: mod.add=" + attribute);
                        }
                        modificationSet.add(LDAPModification.ADD,
                                attribute);
                    }
                } else {
                    LDAPAttribute attribute =
                            (LDAPAttribute) attributes.get(attr);
                    if (attribute != null) {
                        if (Debug.isEnabled()) {
                            Debug.println("ResourcePageObservable.save: mod.rep=" + attribute);
                        }
                        modificationSet.add(LDAPModification.REPLACE,
                                attribute);
                    }
                }
            }

            LDAPConnection ldapConnection = _info.getUserLDAPConnection();
            try {
                String DN = _entry.getDN();
                String unescDN = LDAPUtil.unEscapeDN(DN);
                boolean needesc = !unescDN.equals(DN);
                String newRdnValue = get(_sIndexAttribute, 0);
                if (newRdnValue == null || newRdnValue.trim().equals("")) {
                    _sIndexAttribute = "cn";
                    newRdnValue = get(_sIndexAttribute, 0);
                }
                String newRDN = _sIndexAttribute + "=" + newRdnValue;
                String newRDNEsc = _sIndexAttribute + "=" + LDAPUtil.escapeDNVal(newRdnValue);
                
                //for a group there is no ou so we have to check
                String[] rdns = LDAPDN.explodeDN(DN, false);
                String sDN = "";
                if (rdns.length > 1) {
                    String RDN = rdns[0];
                    StringBuffer newBaseDN = new StringBuffer();
                    for (int i=1; i<rdns.length; i++) {
                        newBaseDN.append(",");
                        newBaseDN.append(rdns[i]);
                    }

                    Debug.println(6, "ResourcePageObservable.save: RDN=" + RDN);
                    Debug.println(6, "ResourcePageObservable.save: newRDN=" + newRDN);
                    Debug.println(6, "ResourcePageObservable.save: newRDNEsc=" + newRDNEsc);
                    if (DN.length() > 0 &&
                    	((new RDN(newRDN)).equals(new RDN(RDN)) == false) &&
                    	((new RDN(newRDNEsc)).equals(new RDN(RDN)) == false)) {
                        Debug.println("ResourcePageObservable.save: rename " + DN + " --> new rdn=" + newRDN);
                        ldapConnection.rename(DN, newRDN, true); // Cannot rename same RDN.
                    }
                    if (needesc) {
                    	sDN = newRDNEsc + newBaseDN.toString();
                    } else {
                    	sDN = newRDN + newBaseDN.toString();
                    }
                } else {
                    sDN = _entry.getDN();
                }

                // for (int i = 0; i < modificationSet.size(); i++) {
                //     Debug.println("ResourcePageObservable.save: perform mod=" + modificationSet.elementAt(i));
                //     ldapConnection.modify(sDN, modificationSet.elementAt(i));
                // }
                ldapConnection.modify(sDN, modificationSet);

                _entry = ldapConnection.read(sDN);
                refresh(false);
            } catch (LDAPException e) {
                Debug.println(0, "ResourcePageObservable.java:MODIFY LDAP ENTRY:"+e);
                throw e;
            }
        }
        return _entry;
    }

    /**
      * remove all the elements in the observable and reload all the values
     * @param newEntry TODO
      */
    public void refresh(boolean newEntry) {
        attrAdd.removeAllElements();
        attrReplace.removeAllElements();
        attrDelete.removeAllElements();

        if (_entry == null) {
            return;
        }

        // read in the new attributes
        attributes.clear();
        _entry = getLDAPEntry(_entry.getDN(), newEntry);
        if (_entry != null) {
        	LDAPAttributeSet attrSet = _entry.getAttributeSet();
        	String attr = null;
        	for (int i = 0; i < attrSet.size(); i++) {
        		attr = attrSet.elementAt(i).getName().toLowerCase();
        		attributes.put(attr, attrSet.elementAt(i));
        	}
        }
    }


    /**
     * Determines whether the directory server is version 4.0.
     *
     * @return  true if DS is 4.0; false otherwise
     */
    private boolean isDirectoryVersion40() {
        try {
            LDAPConnection ldc = _info.getUserLDAPConnection();
            LDAPEntry entry = ldc.read("");
            String suffix = LDAPUtil.flatting(entry.getAttribute("netscapemdsuffix"));
            if ((suffix != null) && (suffix.equals("") == false)) {
                return true;
            }
        } catch (LDAPException e) {
            Debug.println(0,
                    "ERROR ResourcePageObservable.isDirectoryVersion40: failed to determine server version: " + e);
        }

        return false;
    }


    /**
     * Determines whether the user entry already exists in the directory server.
     *
     * @param uid  the user entry to test
     * @return     true if user entry exists; false otherwise
     */
    private boolean uidAlreadyExists(String uid) {
        try {
            String filter = "(&(objectclass=person)(uid=" + uid + "))";
            LDAPConnection ldc = _info.getUserLDAPConnection();
            LDAPSearchResults result = ldc.search(_info.getUserBaseDN(),
                    LDAPConnection.SCOPE_SUB, filter, null, false);
            if (result.hasMoreElements()) {
                if (result.nextElement() instanceof LDAPEntry) {
                    return true;
                }
            }
        } catch (LDAPException e) {
            Debug.println(0,
                    "ERROR ResourcePageObservable.uidAlreadyExists: search failed for " +
                    uid + ": " + e);
        }

        return false;
    }


    /**
     * Attribute value to be added to the entry. The attribute does not
     * previously exist.
     *
     * @param attr   the attribute
     * @param value  the byte array value
     */
    void addAttributeEntry(String attr, Object value) {
        String attrLC = attr.toLowerCase();
        AttributeValuePair attributeValPair =
                new AttributeValuePair(attrLC, value);
        attributes.put(attrLC, attributeValPair.getLDAPAttribute());
        attrAdd.addElement(attributeValPair);
    }


    /**
     * Attribute value to be replaced in the entry.
     *
     * @param attr  the attribute
     */
    public void replaceAttr(String attr) {
        // if attrAdd/attrDelete contain this attribute, remove it.
        String attrLC = attr.toLowerCase();
        boolean newAttr = false;

        Enumeration e = attrAdd.elements();
        while (e.hasMoreElements()) {
            AttributeValuePair aAddPair =
                    (AttributeValuePair)(e.nextElement());
            if (aAddPair.getAttribute().equals(attrLC)) {
                attrAdd.removeElement(aAddPair);
                newAttr = true;
            }
        }

        e = attrDelete.elements();
        while (e.hasMoreElements()) {
            AttributeValuePair aDeletePair =
                    (AttributeValuePair)(e.nextElement());
            if (aDeletePair.getAttribute().equals(attrLC)) {
                attrDelete.removeElement(aDeletePair);
            }
        }

        if (newAttr) {
            LDAPAttribute attrObj = (LDAPAttribute)attributes.get(attrLC);
            // After a modification the attr is left with no values, remove it
            if (attrObj.size() == 0) {
                attributes.remove(attrLC);
            }
            else {
                // Updtate the new attr to be added
                attrAdd.addElement(new AttributeValuePair(attrLC, attrObj));
            }
        }
        else if (!(attrReplace.contains(attrLC))) {
            attrReplace.addElement(attrLC);
        }
    }


    /**
     * Gets an enumeration of all attributes for the LDAP entry.
     *
     * @return  an enumeration of all attributes for the LDAP entry
     */
    public Enumeration getAttributesList() {
        return attributes.keys();
    }


    /**
     * Attribute value to be added to the entry.
     *
     * @param attr   the attribute
     * @param value  the byte array value
     */
    public void add(String attr, byte value[]) {
        String attrLC = attr.toLowerCase();
        if (attributes.containsKey(attrLC)) {
            LDAPAttribute tmp = (LDAPAttribute)(attributes.get(attrLC));
            tmp.addValue(value);
            attributes.put(attrLC, tmp);
            attrAdd.addElement(new AttributeValuePair(attrLC, tmp));
        } else {
            addAttributeEntry(attrLC, value);
        }

        setChanged();
        notifyObservers(attrLC);
    }


    /**
     * Attribute value to be added to the entry.
     *
     * @param attr   the attribute
     * @param value  the string value
     */
    public void add(String attr, String value) {
        String attrLC = attr.toLowerCase();
        if (attributes.containsKey(attrLC)) {
            LDAPAttribute tmp = (LDAPAttribute)(attributes.get(attrLC));
            tmp.addValue(value);
            attributes.put(attrLC, tmp);
            attrAdd.addElement(new AttributeValuePair(attrLC, tmp));
        } else {
            addAttributeEntry(attrLC, value);
        }

        setChanged();
        notifyObservers(attrLC);
    }


    /**
     * Attribute value to be added to the entry.
     *
     * @param attr  the attribute
     * @param v     the vector value
     */
    public void add(String attr, Vector v) {
        String attrLC = attr.toLowerCase();
        if (attributes.containsKey(attrLC)) {
            LDAPAttribute tmp = (LDAPAttribute)(attributes.get(attrLC));
            Enumeration e = v.elements();
            while (e.hasMoreElements()) {
                Object o = e.nextElement();
                if (o instanceof String) {
                    tmp.addValue((String) o);
                } else {
                    tmp.addValue((byte []) o);
                }
            }
            attributes.put(attrLC, tmp);
            attrAdd.addElement(new AttributeValuePair(attrLC, tmp));
        } else {
            addAttributeEntry(attrLC, v);
        }

        setChanged();
        notifyObservers(attrLC);
    }


    /**
      * Delete an existing attribute value.
      *
      * @param attr       the attribute
      * @param value_str  the string value
      */
    public void delete(String attr, String value_str) {
        universalDelete(attr, value_str);
    }


    /**
      * Delete an existing attribute value.
      *
      * @param attr            the attribute
      * @param value_byteArray byte array value
      */
    public void delete(String attr, byte[] value_byteArray) {
        universalDelete(attr, value_byteArray);
    }

    /**
      * Delete an existing attribute value.
      *
      * @param attr         the attribute
      * @param value_vector vector contain values to be deleted
      */
    public void delete(String attr, Vector value_vector) {
        Enumeration e = value_vector.elements();
        while (e.hasMoreElements()) {
            universalDelete(attr, e.nextElement());
        }
    }


    /**
      * Delete an existing attribute value.
      *
      * @param attr     the attribute
      * @param object   the object value, either string or byte array
      */
    private void universalDelete(String attr, Object val) {
        String attrLC = attr.toLowerCase();
        try {
            if (attributes.containsKey(attrLC)) {
                LDAPAttribute tmp = null;

                if ((val == null) || ((val instanceof String) &&
                        ((String) val).equals("")) ||
                        ((val instanceof byte[]) &&
                        (((byte[]) val).length == 0))) {
                    tmp = new LDAPAttribute(attrLC);
                } else {
                    tmp = (LDAPAttribute)(attributes.get(attrLC));
                    if (val instanceof String) {
                        tmp.removeValue((String) val);
                    } else {
                        tmp.removeValue((byte[]) val);
                    }
                }
                attributes.put(attrLC, tmp);
                // remove the add/replace attribute from the vector
                Enumeration eAdds = attrAdd.elements();
                boolean fNeedToDelete = true;
                while (eAdds.hasMoreElements()) {
                    AttributeValuePair aPair =
                            (AttributeValuePair)(eAdds.nextElement());
                    if (aPair.getAttribute().equals(attrLC)) {
                        fNeedToDelete = false;
                        attrAdd.removeElement(aPair);
                    }
                }
                if (attrReplace.contains(attrLC)) {
                    attrReplace.removeElement(attrLC);
                }
                if (fNeedToDelete) {
                    attrDelete.addElement(
                            new AttributeValuePair(attrLC, tmp));
                }
                attributes.remove(attrLC);
            }
        } catch (Exception e) {
            Debug.println(0, "ResourcePageObservable:"+e);
        }
        setChanged();
        notifyObservers(attrLC);
    }


    /**
      * Delete all attribute values.
      *
      * @param attr  the attribute
      */
    public void delete(String attr) {
        String attrLC = attr.toLowerCase();
        if (attributes.containsKey(attrLC)) {
            LDAPAttribute tmp = new LDAPAttribute(attrLC);
            attributes.put(attrLC, tmp);
            // remove the add/replace attribute from the vector
            Enumeration eAdds = attrAdd.elements();
            boolean fNeedToDelete = true;
            while (eAdds.hasMoreElements()) {
                AttributeValuePair aPair =
                        (AttributeValuePair)(eAdds.nextElement());
                if (aPair.getAttribute().equals(attrLC)) {
                    fNeedToDelete = false;
                    attrAdd.removeElement(aPair);
                }
            }
            if (attrReplace.contains(attrLC)) {
                attrReplace.removeElement(attrLC);
            }
            if (fNeedToDelete) {
                attrDelete.addElement(new AttributeValuePair(attrLC, tmp));
            }
            attributes.remove(attrLC);
        }
        setChanged();
        notifyObservers(attrLC);
    }


    /**
      * Replace the attribute value with a new value.
      *
      * @param attr      Attribute name
      * @param newValue  New value to replace the old
      */
    public void replace(String attr, String newValue) {
        String attrLC = attr.toLowerCase();
        if (attributes.containsKey(attrLC)) {
            LDAPAttribute attribute = new LDAPAttribute(attrLC, newValue);
            LDAPAttribute oldAttr = (LDAPAttribute)attributes.get(attrLC);
            if (!(compareAttrValues(oldAttr, attribute))) {
                attributes.put(attrLC.toLowerCase(), attribute);
                replaceAttr(attrLC);
            }
        } else {
            addAttributeEntry(attrLC, newValue);
        }

        setChanged();
        notifyObservers(attrLC);
    }

    /**
     * Compare case-sensitive attribute values in the original attribute
     * with those read from the UI panel
     */
    boolean compareAttrValues(LDAPAttribute attr1, LDAPAttribute attr2) {
        String[] val1 = attr1.getStringValueArray();
        String[] val2 = attr2.getStringValueArray();
        
        if (val1.length != val2.length) {
            return false;
        }
        
        for (int i=0; i < val1.length; i++) {
            if (!val1[i].equals(val2[i])) {
                return false;
            }
        }
        
        return true;
    }

    /**
      * Replace the attribute value with a new value.
      *
      * @param attr  Attribute name
      * @param v     New vector value to replace the old
      */
    public void replace(String attr, Vector v) {
        String attrLC = attr.toLowerCase();
        if (attributes.containsKey(attrLC)) {
            Enumeration e = v.elements();
            LDAPAttribute attribute = new LDAPAttribute(attrLC);
            while (e.hasMoreElements()) {
                Object o = e.nextElement();
                if (o instanceof String) {
                    attribute.addValue((String) o);
                } else {
                    attribute.addValue((byte[]) o);
                }
            }
            LDAPAttribute oldAttr = (LDAPAttribute)attributes.get(attrLC);
            if (!(compareAttrValues(oldAttr, attribute))) {
                attributes.put(attrLC.toLowerCase(), attribute);
                replaceAttr(attrLC);
            }
        } else {
            addAttributeEntry(attrLC, v);
        }
        setChanged();
        notifyObservers(attrLC);
    }


    /**
      * Replace the attribute value with a new value.
      *
      * @param attr  Attribute name
      * @param v     New byte array value to replace the old
      */
    public void replace(String attr, byte v[]) {
        String attrLC = attr.toLowerCase();
        if (attributes.containsKey(attrLC)) {
            LDAPAttribute attribute = new LDAPAttribute(attrLC, v);
            LDAPAttribute oldAttr = (LDAPAttribute)attributes.get(attrLC);
            if (!(compareAttrValues(oldAttr, attribute))) {
                attributes.put(attrLC.toLowerCase(), attribute);
                replaceAttr(attrLC);
            }
        } else {
            addAttributeEntry(attrLC, v);
        }
        setChanged();
        notifyObservers(attrLC);
    }


    /**
      * Get all attribute value.
      *
      * @param attr   Attribute name
      * @return       the Vector containing all the attribute values
      */
    public Vector get(String attr) {
        String attrLC = attr.toLowerCase();

        Vector nReturn = new Vector();
        LDAPAttribute attribute = (LDAPAttribute)(attributes.get(attrLC));
        if (attribute != null) {
            Enumeration e = attribute.getStringValues();
            while (e.hasMoreElements()) {
                nReturn.addElement(e.nextElement());
            }
        }
        return nReturn;
    }


    /**
      * Returns the first byte array for the attribute.
      *
      * @param attr   Attribute name
      * @return       the byte array
      */
    public byte[] getBytes(String attr) {
        String attrLC = attr.toLowerCase();

        LDAPAttribute attribute = (LDAPAttribute) attributes.get(attrLC);
        byte bReturn[] = null;
        if (attribute != null) {
            Enumeration e = attribute.getByteValues();
            if (e != null) {
                if (e.hasMoreElements()) {
                    bReturn = (byte[]) e.nextElement();
                }
            }
        }
        return bReturn;
    }


    /**
      * Returns the first byte vector for the attribute.
      *
      * @param attr   Attribute name
      * @return       the enumeration for the byte values
      */
    public Enumeration getBytesVector(String attr) {
        String attrLC = attr.toLowerCase();

        LDAPAttribute attribute = (LDAPAttribute) attributes.get(attrLC);
        Enumeration eReturn = null;
        if (attribute != null) {
            eReturn = attribute.getByteValues();
        }
        return eReturn;
    }


    /**
      * Get all attribute values.
      *
      * @param attr  Attribute name
      * @return      String containing all attribute values that were separated by ','
      */
    public String getValues(String attr) {
        String attrLC = attr.toLowerCase();

        LDAPAttribute tmp = (LDAPAttribute)(attributes.get(attrLC));
        StringBuffer nReturn = new StringBuffer("");
        if (tmp != null) {
            Enumeration eString = tmp.getStringValues();
            if (eString != null) {
                while (eString.hasMoreElements()) {
                    nReturn.append((String)(eString.nextElement()));
                    if (eString.hasMoreElements())
                        nReturn.append(",");
                }
            }
        }
        return nReturn.toString();
    }


    /**
      * Get all attribute values.
      *
      * @param attr  Attribute name
      * @return      String array containing all attribute values, or null
      */
    public String[] getValueArray(String attr) {
        String attrLC = attr.toLowerCase();

        LDAPAttribute tmp = (LDAPAttribute)(attributes.get(attrLC));
        String sReturn[] = null;
        if (tmp != null) {
            sReturn = convertEnumToArray(tmp.getStringValues());
        }
        return sReturn;
    }


    /**
      * Converts the specified enumerated values to a String array.
      *
      * @param tmp  enumerated values
      * @return     String array
      */
    public String[] convertEnumToArray(Enumeration tmp) {
        if (tmp == null) {
            return null;
        }
        Vector vVector = new Vector();
        while (tmp.hasMoreElements()) {
            vVector.addElement(tmp.nextElement());
        }
        int iCount = vVector.size();
        String values[] = new String[iCount];

        Enumeration e = vVector.elements();
        for (int i = 0; e.hasMoreElements(); i++) {
            values[i] = (String) e.nextElement();
        }

        return values;
    }


    /**
      * Gets the attribute value at the specified index.
      *
      * @param  attr   Attribute name
      * @param  index  the value at this index
      * @return        Nth attribute value, "" if index >= numbers attribute values
      */
    public String get(String attr, int index) {
        String attrLC = attr.toLowerCase();

        LDAPAttribute tmp = (LDAPAttribute)(attributes.get(attrLC));
        String nReturn = "";
        if (tmp != null) {
            Enumeration eString = tmp.getStringValues();
            int iCount = 0;
            while (eString.hasMoreElements()) {
                String sString = (String) eString.nextElement();
                if (iCount == index) {
                    nReturn = sString;
                    break;
                }
            }
        }

        return(nReturn == null ? "":nReturn);
    }


    /**
     * Determines whether the observable object is a new user.
     *
     * @return  true if it refers to a new user; false otherwise
     */
    public boolean isNewUser() {
        return _fNewUser;
    }


    /**
     * Gets the language lists in the entry.
     *
     * @return  String array containing the language list
     */
    public String[] getLanguages() {
        if (_entry != null)
            return LDAPUtil.getAttributeLanguages(_entry);
        else
            return null;
    }

    /**
     * Returns a string representation of the object.
     * @return a string representation of the object.
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("ResourcePageObservable:");
        sb.append("\n\tnewUser=");
        sb.append(_fNewUser);
        sb.append("\n\tsBaseDN=");
        sb.append(_sBaseDN);
        
        sb.append("\n\tobjectClassList=");
        for (int i=0; _objectClassList != null && i <_objectClassList.size(); i++) {
            sb.append(_objectClassList.elementAt(i));
            sb.append(" ");
        }
        
        sb.append("\n\tattributes=");
        sb.append(attributes.toString());
        
        sb.append("\n\tattrAdd=");
        for (int i=0; attrAdd != null && i <attrAdd.size(); i++) {
            sb.append(attrAdd.elementAt(i));
            sb.append(" ");
        }        
        sb.append("\n\tattrReplace=");
        for (int i=0; attrReplace != null && i <attrReplace.size(); i++) {
            sb.append(attrReplace.elementAt(i));
            sb.append(" ");            
        }
        sb.append("\n\tattrDelete=");
        for (int i=0; attrDelete != null && i <attrDelete.size(); i++) {
            sb.append(attrDelete.elementAt(i));
            sb.append(" ");            
        }
        
        sb.append("\n\tentry=");
        sb.append(_entry);
        sb.append("\n");
        
        return sb.toString();
    }
}


/**
  * AttributeValuePair is a helper class to hold attribute value pairs.
  */
class AttributeValuePair {
    String attribute;
    LDAPAttribute attributeValue;


    /**
    * Constructor
    *
    * @param attr  the attribute
    * @param val   the value
    */
    /*public AttributeValuePair(String attr, LDAPAttribute val) {
    	attribute      = attr;
    	attributeValue = val;
}*/

    public AttributeValuePair(String attr, Object val) {
        attribute = attr;
        if (val instanceof LDAPAttribute) {
            attributeValue = (LDAPAttribute) val;
        } else if (val instanceof String) {
            attributeValue = new LDAPAttribute(attribute, (String) val);
        } else if (val instanceof byte[]) {
            attributeValue = new LDAPAttribute(attribute, (byte[]) val);
        } else if (val instanceof Vector) {
            Enumeration e = ((Vector) val).elements();
            attributeValue = new LDAPAttribute(attribute);
            while (e.hasMoreElements()) {
                Object tmpVal = e.nextElement();
                if (tmpVal instanceof String) {
                    attributeValue.addValue((String) tmpVal);
                } else {
                    attributeValue.addValue((byte[]) tmpVal);
                }
            }
        }
    }


    /**
     * Retrieves the value.
     *
     * @return  the value (LDAPAttribute)
     */
    public LDAPAttribute getLDAPAttribute() {
        return attributeValue;
    }


    /**
     * Retrieves the attribute.
     *
     * @return  the attribute
     */
    public String getAttribute() {
        return attribute;
    }

    /**
     * Returns a string representation of the object.
     * @return a string representation of the object.
     */    
    public String toString() {
        return "AttributeValuePair: " + attribute + " " + attributeValue;
    }
}
