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
import java.awt.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;


/**
 * LanguagePage is a plugin for the ResourceEditor. It lets users select
 * a preferred language and specify information such as a person's name to
 * be displayed. The LanguagePage creates the ILanguageFactory object
 * based on the object classes that it is initialized with. The
 * ILanguageFactory object generates the pages for the languages specified
 * in a properties file.
 *
 * @see IResourceEditorPage
 * @see ILanguageFactory
 */
public class LanguagePage extends JPanel implements IResourceEditorPage,
                                                    Observer, ListSelectionListener {
    static Vector _vUserSection = null;
    static Vector _vGroupSection = null;
    static Vector _vOUSection = null;

    static private Font fNormal = null;
    static private Font fBold = null;

    Vector _vMapping = null;
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();

    LanguageModel _dataModel;

    Hashtable _hPages;
    Hashtable _languageTags;
    IResourceEditorPage _CurrentPage = null;

    static final int _USER = 1;
    static final int _GROUP = 2;
    static final int _OU = 3;

    ILanguageFactory _languageFactory;

    private int _objectType = _USER;
    private String ID;

    private JPanel _containerPane;
    private JList _listLanguage;
    private int _oldSelection = 0;
    private JComboBox _preferredLangCombo;

    ResourceEditor _parent;
    ResourcePageObservable _observable;


    /**
     * Constructor
     */
    public LanguagePage() {
        super(true);
        setLayout(new GridBagLayout());
        _hPages = new Hashtable();
        _languageTags = new Hashtable();
        ID = _resource.getString("languageTab","ID");
    }


    /**
     * Implements Observer interface. Propagates update information to all
     * pages.
     *
     * @param o    the observable object
     * @param arg  the argument
     */
    public void update(Observable o, Object arg) {
        _observable = (ResourcePageObservable) o;
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                if (page instanceof Observer) {
                    Observer observer = (Observer) page;
                    observer.update(o, arg);
                }
            }
        }
    }


    /**
     * Implements the IResourceEditorPage interface. Initializes the page.
     * Based on the object classes for the observable, this creates the
     * appropriate language factory to generate the pages to display.
     *
     * @param observable  the observable
     * @param parent      the ResourceEditor container
     */
    public void initialize(ResourcePageObservable observable,
                           ResourceEditor parent) {
        _parent = parent;
        _observable = observable;
        Vector vObjectClass = observable.get("objectclass");
        Enumeration e = vObjectClass.elements();
        while (e.hasMoreElements()) {
            String sObjectClass = (String) e.nextElement();
            if (sObjectClass.equalsIgnoreCase("person")) {
                _objectType = _USER;
                _languageFactory = new UserLanguageFactory();
                break;
            } else if (sObjectClass.equalsIgnoreCase("groupofuniquenames")) {
                _objectType = _GROUP;
                _languageFactory = new GroupLanguageFactory();
                break;
            } else if (sObjectClass.equalsIgnoreCase("organizationalunit")) {
                _objectType = _OU;
                _languageFactory = new OULanguageFactory();
                break;
            }
        }

        _dataModel = new LanguageModel();

        if (_vMapping == null)
            initMapping(parent.getConsoleInfo());

        if (_objectType == _USER) {
            _dataModel.setData(_vMapping, _languageTags,
                               observable.get("PreferredLanguage"));
        } else {
            _dataModel.setData(_vMapping, null, null);
        }

        setupUI();

        _listLanguage.setSelectedIndex(0);
    }


    class LangListCellRender extends JLabel implements ListCellRenderer {
        LangListCellRender() {
            setOpaque(true);
        }

        public Component getListCellRendererComponent(JList list,
                                                      Object value, int index, boolean isSelected,
                                                      boolean cellhasFocus) {
            if (value != null) {
                if (fNormal == null || fBold == null) {
                    Font tmp = getFont();
                    fNormal = new Font(tmp.getFamily(), Font.PLAIN,
                                       tmp.getSize());
                    fBold = new Font(tmp.getFamily(), Font.BOLD,
                                     tmp.getSize());
                }

                if (value instanceof String) {
                    IResourceEditorPage page =
                        (IResourceEditorPage)_hPages.get(value);
                    if (page == null) {
                        page = (IResourceEditorPage)
                            _languageFactory.getPage(
                                                     (String)_languageTags.get(value));
                    }
                    if (page instanceof ILocalize) {
                        setFont((((ILocalize) page).isLocalize()) ?
                                fBold : fNormal);
                    }
                }
                setText((String) value);
                setBackground(isSelected ?
                              UIManager.getColor("List.selectionBackground")
                              : UIManager.getColor("List.background"));
                setForeground(isSelected ?
                              UIManager.getColor("List.selectionForeground")
                              : UIManager.getColor("List.foreground"));
            }
            return this;
        }
    }

    /**
     * Convenience routine to layout the visual components.
     */
    private void setupUI() {
        removeAll();

        JLabel label = new JLabel(_resource.getString("languageTab","label"));
        GridBagUtil.constrain(this, label, 0, 0,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        _listLanguage = new JList(_dataModel);
        _listLanguage.getSelectionModel().addListSelectionListener(this);
        _listLanguage.getSelectionModel().setSelectionMode(
                                                           ListSelectionModel.SINGLE_SELECTION);

        // Show colors by rendering them in their own color.

        int iRow = 1;
        if (_objectType == _USER) {
            label = new JLabel(_resource.getString("languageTab","pref"));
            GridBagUtil.constrain(this, label, 0, iRow++, 1, 1, 0.0,
                                  0.0, GridBagConstraints.NORTHWEST,
                                  GridBagConstraints.HORIZONTAL,
                                  SuiLookAndFeel.VERT_WINDOW_INSET,
                                  SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _preferredLangCombo = new JComboBox(_dataModel);
            label.setLabelFor(_preferredLangCombo);
            GridBagUtil.constrain(this, _preferredLangCombo, 0, iRow++,
                                  1, 1, 0.0, 0.0, GridBagConstraints.NORTHWEST,
                                  GridBagConstraints.HORIZONTAL,
                                  SuiLookAndFeel.VERT_WINDOW_INSET,
                                  SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        }

        label = new JLabel(_resource.getString("languageTab","availLang"));
        label.setLabelFor(_listLanguage);
        GridBagUtil.constrain(this, label, 0, iRow++, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        
        LangListCellRender fontRenderer = new LangListCellRender();
        _listLanguage.setCellRenderer(fontRenderer);

        JScrollPane pane = new JScrollPane(_listLanguage);
        pane.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));
        GridBagUtil.constrain(this, pane, 0, iRow, 1,
                              GridBagConstraints.REMAINDER, 0.0, 1.0,
                              GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                              SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET,
                              SuiLookAndFeel.VERT_WINDOW_INSET, 0);

        _containerPane = new JPanel();
        _containerPane.setBorder( new TitledBorder(new EtchedBorder(),
                                                   _resource.getString("languageTab", "info")));
        _containerPane.setSize(450, 400);
        _containerPane.setLayout(new BorderLayout());
        GridBagUtil.constrain(this, _containerPane, 1, 1,
                              GridBagConstraints.REMAINDER,
                              GridBagConstraints.REMAINDER, 1.0, 1.0,
                              GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                              SuiLookAndFeel.SEPARATED_COMPONENT_SPACE / 2,
                              SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

    }


    /**
     * Convenience routine to display the page for the selected language.
     *
     * @param index  the selected language
     */
    private void selectPanel(String index) {
        _containerPane.removeAll();

        Component c = (Component)_hPages.get(index);
        if (c == null) {
            IResourceEditorPage page =
                (IResourceEditorPage)_languageFactory.getPage(
                                                              (String)_languageTags.get(index));
            page.initialize(_observable, _parent);
            _hPages.put(index, page);
            c = (Component) page;
        }
        _containerPane.add("Center",c);
        _CurrentPage = (IResourceEditorPage) c;
        validate();
        repaint();
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#getID
     */
    public String getID() {
        return ID;
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#afterSave(ResourcePageObservable)
     */
    public boolean afterSave(ResourcePageObservable observable)
        throws Exception {
        Enumeration keys = _hPages.keys();
        boolean fReturn = true;

        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                fReturn &= page.afterSave(observable);
            }
        }
        return fReturn;
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#save(ResourcePageObservable)
     */
    public boolean save(ResourcePageObservable observable)
        throws Exception {
        Enumeration keys = _hPages.keys();
        boolean fReturn = true;

        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                fReturn &= page.save(observable);
            }
        }

        if (_objectType == _USER) {
            // remember to save the preferred language
            String sPreferredLanguage = null;
            if (_dataModel.getSelectedItem() != null) {
                sPreferredLanguage = (String)_languageTags.get(
                                                               _dataModel.getSelectedItem());
            }
            if (sPreferredLanguage == null) {
                observable.delete("preferredlanguage");
            } else {
                observable.replace("preferredlanguage",sPreferredLanguage);
            }
        }
        return fReturn;
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#clear
     */
    public void clear() {
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                page.clear();
            }
        }
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#reset
     */
    public void reset() {
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                page.reset();
            }
        }
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#setDefault
     */
    public void setDefault() {
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                page.setDefault();
            }
        }
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#isModified
     */
    public boolean isModified() {
        boolean fModified = true;
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                fModified &= page.isModified();
            }
        }
        return fModified;
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#setModified(boolean)
     */
    public void setModified(boolean fModified) {
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                page.setModified(fModified);
            }
        }
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#isReadOnly
     */
    public boolean isReadOnly() {
        boolean fReadOnly = true;
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                fReadOnly &= page.isReadOnly();
            }
        }
        return fReadOnly;
    }

    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#setReadOnly(boolean)
     */
    public void setReadOnly(boolean fState) {
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                page.setReadOnly(fState);
            }
        }
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#setEnable(boolean)
     */
    public void setEnable(boolean fEnable) {
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                page.setEnable(fEnable);
            }
        }
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#isComplete
     */
    public boolean isComplete() {
        boolean fReturn = true;
        Enumeration keys = _hPages.keys();
        while (keys.hasMoreElements()) {
            String sIndex = (String) keys.nextElement();
            IResourceEditorPage page =
                (IResourceEditorPage)_hPages.get(sIndex);
            if (page != null) {
                fReturn &= page.isComplete();
            }
        }
        return fReturn;
    }


    /**
     * Implements the IResourceEditorPage interface.
     *
     * @see IResourceEditorPage#getDisplayName
     */
    public String getDisplayName() {
        return ID;
    }

    private Vector getSectionPlugin(String sSectionName) {
        int iPluginCount =
            Integer.parseInt(_resource.getString(sSectionName, "pluginCount"));
        Vector vReturn = new Vector();
        for (int i = 0; i < iPluginCount; i++) {
            String sTag = _resource.getString(sSectionName, "plugin"+i);
            vReturn.addElement(sTag);
        }
        return vReturn;
    }

    Vector getLocalizeList() {
        Vector v = new Vector();
        Enumeration e = _observable.getAttributesList();
        while (e.hasMoreElements()) {
            String sAttribute = (String) e.nextElement();
            int iIndex = sAttribute.lastIndexOf(";lang-");
            if (iIndex >= 0) {
                String sTag = sAttribute.substring(iIndex + 6, iIndex + 8);
                if (!v.contains(sTag)) {
                    v.addElement(sTag);
                }
            }
        }
        return v;
    }

    /**
     * Sets up the association between the table entries on the left and the
     * language specific page on the right of the display.
     *
     * @param info  session information
     */
    void initMapping(ConsoleInfo info) {
        int i;
        _vMapping = new Vector();
        Vector vSection = null;
        switch (_objectType) {
        case _USER:
            if (_vUserSection == null) {
                _vUserSection = getSectionPlugin("userPage"); // Returns all of the language tags, i.e. af, sq, ...
            }
            vSection = _vUserSection;
            break;
        case _GROUP:
            if (_vGroupSection == null) {
                _vGroupSection = getSectionPlugin("GroupPage"); // Returns all of the language tags, i.e. af, sq, ...
            }
            vSection = _vGroupSection;
            break;
        case _OU:
            if (_vOUSection == null) {
                _vOUSection = getSectionPlugin("OUPage"); // Returns all of the language tags, i.e. af, sq, ...
            }
            vSection = _vOUSection;
            break;
        }

        Vector vLocalizeList = getLocalizeList();

        Enumeration eSection = vSection.elements();
        while (eSection.hasMoreElements()) {
            String sTag = (String) eSection.nextElement();
            String sLanguage = _resource.getString("userPage",sTag);
            _languageTags.put(sLanguage, sTag); // Need to keep track of tags to return as preferred language
            _vMapping.addElement(sLanguage);
            if (vLocalizeList.contains(sTag)) {
                IResourceEditorPage page =
                    (IResourceEditorPage)_languageFactory.getPage(
                                                                  sTag);
                if (page instanceof ILocalize) {
                    ((ILocalize) page).setLocalize(true);
                }
            }
            //IResourceEditorPage page = (IResourceEditorPage)_languageFactory.getPage(sTag);
            //if(page!=null)
            //{
            //	String sLanguage=_resource.getString("userPage",sTag);
            //	_hPages.put(sLanguage, page);
            //	_languageTags.put(sLanguage, sTag);	// Need to keep track of tags to return as preferred language
            //	_vMapping.addElement(sLanguage);
            //}
        }
    }


    /**
     * Implements the ListSelectionListener interface. Displays the
     * page for the language that has been selected.
     *
     * @param e  the list selection event
     */
    public void valueChanged(ListSelectionEvent e) {
        //change selection
        String sIndex = (String)_vMapping.elementAt(_oldSelection =
                                                    _listLanguage.getSelectedIndex());
        selectPanel(sIndex);
    }


    /**
     * Implements the IResourceEditorPage interface. Displays help
     * for the currently displayed language page.
     *
     * @see IResourceEditorPage#help
     */
    public void help() {
        if (_CurrentPage != null) {
            _CurrentPage.help();
        }
    }
}


/**
  * LanguageTableModel is the model for the table used to display the list
  * of supported languages.
  */
class LanguageModel extends DefaultListModel implements ComboBoxModel {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    Vector _vLanguage;
    Hashtable _languageTags;
    String _sPreferredLanguage = null;

    public LanguageModel() {
    }

    public void setData(Vector vLanguage, Hashtable languageTags,
                        Vector vPreferredLanguage) {
        _vLanguage = vLanguage;
        _languageTags = languageTags;
        // set the preferred language
        if ((vPreferredLanguage != null) &&
            (vPreferredLanguage.size() > 0)) {
            _sPreferredLanguage = _resource.getString("userPage",
                                                      (String) vPreferredLanguage.elementAt(0));
        }

        // add the items
        Enumeration eLanguage = vLanguage.elements();
        while (eLanguage.hasMoreElements()) {
            addElement(eLanguage.nextElement());
        }
    }

    public void setSelectedItem(Object o) {
        _sPreferredLanguage = (String) o;
    }

    public Object getSelectedItem() {
        return _sPreferredLanguage;
    }
}

