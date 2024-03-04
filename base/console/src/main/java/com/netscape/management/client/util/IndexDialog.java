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

package com.netscape.management.client.util;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.text.CollationKey;
import java.text.Collator;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URL;

import javax.swing.BorderFactory;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLFrameHyperlinkEvent;

import com.netscape.management.client.components.GenericDialog;
import com.netscape.management.client.console.Console;

/**
 * Dialog to select a topic to display, from a list of URLS organized
 * by index tag
 *
 * @version 1.0
 * @author rweltman
 **/
public class IndexDialog extends GenericDialog
                         implements DocumentListener,
                                    ListSelectionListener,
                                    HyperlinkListener {
    /**
     * Constructs an index selection dialog with the specified parent
     * frame, and reads the index information from a file
     *
     * @param frame Parent frame
     * @param filename name of file containing index descriptions
     */
    public IndexDialog( JFrame frame,
                        String filename ) {
        super( frame, _resource.getString(_section, "title"), CLOSE, HORIZONTAL );
        JList list = populateIndex( filename );
        init( list );
    }

    /**
     * Constructs an index selection dialog with the specified parent
     * frame, and reads the index information from an URL
     *
     * @param frame Parent frame
     * @param url URL of page containing index descriptions
     */
    public IndexDialog( JFrame frame,
                        URL url ) {
        super( frame, _resource.getString(_section, "title"), CLOSE, HORIZONTAL );

        _indexUrl = url.toExternalForm();
        JList list = populateIndex( url );
        init( list );
    }

    /**
     * Does commmon constructor work
     *
     * @param list list component with keywords
     */
    protected void init( JList list ) {
        prepareContentPane( list );
        setDefaultCloseOperation( DISPOSE_ON_CLOSE );
    }

    /**
     * Creates GUI elements and lays them out
     *
     * @param list list box with keywords
     */
    protected void prepareContentPane( JList list ) {
        JPanel contentPane = new JPanel();
        contentPane.setLayout( new GridBagLayout() );
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel lblTypeIn = new JLabel(_resource.getString(_section, "typeInLabel"));
        contentPane.add( lblTypeIn, gbc );

        // Text field to type in characters to match keywords
        _typeInField = new JTextField();
        lblTypeIn.setLabelFor(_typeInField);
        _typeInField.getDocument().addDocumentListener( this );
        _typeInField.setRequestFocusEnabled( true );
        _typeInField.requestFocus();
        contentPane.add( _typeInField, gbc );
        
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE, 0, 0, 0);
        JLabel lblSelectTopic = new JLabel(_resource.getString(_section, "selectTopicLabel"));
        contentPane.add( lblSelectTopic, gbc );
        
        // List of keywords
        _itemList = list;
        JScrollPane listScrollPane = new JScrollPane( _itemList );
        listScrollPane.setPreferredSize( new Dimension( WIDTH, LIST_HEIGHT ) );

        // HTML pane with links to topics

        _pane = new JEditorPane();
        JPanel linkPanel = new JPanel(new GridBagLayout());
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);

        JLabel lblLink = new JLabel(_resource.getString(_section, "selectItemLabel"));
        lblLink.setLabelFor(_pane);

        linkPanel.add( lblLink, gbc );

        JScrollPane linkScrollPane = new JScrollPane( _pane );
        linkScrollPane.setPreferredSize( new Dimension( WIDTH, TOPIC_HEIGHT ) );
        _pane.setContentType( "text/html" );
        _pane.setEditable( false );
        _pane.setBackground( Color.white );
        _pane.addHyperlinkListener( this );
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        linkPanel.add(linkScrollPane, gbc);

        /* debugging code
        HTMLDocument doc = (HTMLDocument)_pane.getDocument();
        
        StyleSheet styles = doc.getStyleSheet();
        Enumeration rules = styles.getStyleNames();
        while (rules.hasMoreElements()) {
            String name = (String) rules.nextElement();
            Style rule = styles.getStyle(name);
            Debug.println(name + ": " + rule.toString());
        }
        */
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, listScrollPane, linkPanel);
        splitPane.setBorder(BorderFactory.createEmptyBorder());
        //splitPane.setResizeWeight(0.6);    // TODO: jdk 1.3
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        contentPane.add( splitPane, gbc );
        
        getContentPane().add(contentPane);
    }

    /**
     * Reads keywords and topics from a file
     *
     * @param filename name of file to read
     * @return a list box with keywords
     */
    protected JList populateIndex( String filename ) {
        try {
            return populateIndex( new BufferedReader(
                new FileReader( filename ) ) );
        } catch ( IOException e ) {
            System.err.println( filename + ": " + e );
        }
        return new JList();
    }

    /**
     * Reads keywords and topics from an URL
     *
     * @param url URL to read from
     * @return a list box with keywords
     */
    protected JList populateIndex( URL url ) {
        try {
            AdmTask admTask = new AdmTask(url, 
                                          Console.getConsoleInfo().getAuthenticationDN(),
                                          Console.getConsoleInfo().getAuthenticationPassword());
            admTask.exec();

            if (admTask.getException() != null) {
                throw admTask.getException();
            }
            

            return populateIndex(new BufferedReader(new StringReader(admTask.getResultString().toString())));
            
        } catch ( Exception e ) {
            System.err.println( url + ": " + e );
        }
        return new JList();
    }

    /**
     * Reads keywords and topics from a stream
     *
     * @param reader stream to read from
     * @return a list box with keywords
     */
    protected JList populateIndex( BufferedReader reader ) {
        try {
            String line;
            Vector keys = new Vector();
            _topics = new Hashtable();
            String base = "";
            while( (line = reader.readLine()) != null ) {
                int ind = line.indexOf( '<' );
                if ( line.startsWith( "<BASEURL" ) ) {
                    base = "<BASE HREF=\"" + getBaseUrl( line ) + "\">";
                    Debug.println( "IndexDialog.populateIndex: base URL " +
                                   "= " + base );
                } else if ( ind > 0 ) {
                    String key = line.substring( 0, ind-1 );
                    String url = line.substring( ind );
                    int brIndex = url.lastIndexOf("<BR>");
                    if(brIndex != -1)
                        url = url.substring(0, brIndex);
                    int i = keys.indexOf( key );
                    if ( i >= 0 ) {
                        String value = (String)_topics.get( key );
                        value += "<BR>" + '\n' + url;
                        _topics.put( key, value );
                    } else {
                        keys.addElement( key );
                        _topics.put( key, base + url );
                    }
                }
            }
            // Create array of collation keys for typedown
            _keys = new CollationKey[keys.size()];
            Enumeration en = keys.elements();
            int i = 0;
            while( en.hasMoreElements() ) {
                _keys[i++] = _collator.getCollationKey(
                    (String)en.nextElement() );
            }
            JList list = new JList( keys );
            list.addListSelectionListener( this );
            list.setSelectionMode( ListSelectionModel.SINGLE_SELECTION );
            return list;
        } catch ( IOException e ) {
            System.err.println( e );
        }
        return new JList();
    }

    /**
     * Implements ListSelectionListener
     *
     * @param e indicates the new selection parameters
     */
    public void valueChanged( ListSelectionEvent e ) {
		if(e.getLastIndex() == _itemList.getModel().getSize())
			return;  // prevent out of bounds exception
		
        String key = (String)_itemList.getSelectedValue();
        String text = (String)_topics.get( key );
        String fontStart = "<FONT FACE=\"sans-serif,helvetica,arial\" SIZE=\"2\">";
        String fontEnd = "</FONT>";
        _pane.setText( fontStart + text + fontEnd );

        if (((HTMLDocument)(_pane.getDocument())).getBase() == null) {
            try {
                ((HTMLDocument)(_pane.getDocument())).setBase(new URL(_indexUrl));
            } catch (Exception e2) {
                Debug.println("IndexDialog.valueChanged() - index url:"+_indexUrl +":"+e2);
            }
        }
    }

    /**
     * Implement the DocumentListener interface.<BR>
     * Catch all changes in the typedown text field and update the
     * scrolling list.
     *
     * @param e The event from the typedown text field Document
     */
    public void changedUpdate(DocumentEvent e) {
        doTypedown();
    }
    /**
     * Implement the DocumentListener interface.<BR>
     * Catch all changes in the typedown text field and update the
     * scrolling list.
     *
     * @param e The event from the typedown text field Document
     */
    public void removeUpdate(DocumentEvent e) {
        doTypedown();
    }
    /**
     * Implement the DocumentListener interface.<BR>
     * Catch all changes in the typedown text field and update the
     * scrolling list.
     *
     * @param e The event from the typedown text field Document
     */
    public void insertUpdate(DocumentEvent e) {
        doTypedown();
    }

    /**
     * Find the first element in the list which is not greater than
     * the typed-in text, and Scroll the list so that index is visible
     */
    private void doTypedown() {
        String text = _typeInField.getText();
        int index = 0;
        int size = _itemList.getModel().getSize();
        CollationKey key = _collator.getCollationKey( text );
        while( (index < size) &&
               key.compareTo( _keys[index] ) > 0 ) {
            index++;
        }
        _itemList.setSelectedIndex( index );
        _itemList.ensureIndexIsVisible( index );
    }

    /**
     * Called when a hyperlink is clicked in the HTML window; records the URL
     * and disposes of the dialog
     *
     * @param e event containing URL info
     */
    public void hyperlinkUpdate( HyperlinkEvent e ) {
        if ( e.getEventType() == HyperlinkEvent.EventType.ACTIVATED ) {
            URL u = e.getURL();

            if ( u == null ) {
                System.err.println( "IndexDialog.hyperlinkUpdate: invalid " +
                                    "URL - " + e.getEventType() + " - " +
                                    e.getDescription() );
                return;
            }
            String url = u.toString();
            JEditorPane pane = (JEditorPane)e.getSource();
            if ( e instanceof HTMLFrameHyperlinkEvent ) {
                Debug.println( "Frame event for URL " + e.getURL() );
                HTMLFrameHyperlinkEvent  evt = (HTMLFrameHyperlinkEvent)e;
                HTMLDocument doc = (HTMLDocument)pane.getDocument();
                doc.processHTMLFrameHyperlinkEvent( evt );
            } else {
                Debug.println( "Setting the URL to " + url );
                int wc = BrowseHtmlDialog.getWindowContext( url );
                Debug.println( "Window context: " + wc );
                _doBrowser = ( (wc == BrowseHtmlDialog.WC_NOCONTEXT) ||
                               (wc == BrowseHtmlDialog.WC_BROWSER) );
                firePropertyChange( PROPERTY_NAME_URL, "", url );
            }
        }
    }

    /**
     * Called when CLOSE button is pressed.
     * Closes and deletes the dialog, and notifies any listeners
     * by sending a <CODE>null</CODE> value for the URL
     */
    protected void closeInvoked() {
        super.closeInvoked();
        dispose();
        firePropertyChange( PROPERTY_NAME_URL, "", null );
    }

    /**
     * Returns the URL of the selected help topic, or "" if none was
     * selected
     *
     * @return selected URL as a String, or "" on Cancel
     */
    public String getUrl() {
        return _url;
    }

    /**
     * Add a client to be notified when an URL is selected
     * @param listener a client to be notified of changes
     */
    public void addPropertyChangeListener( PropertyChangeListener listener ) {
        if (_propSupport != null) {
            _propSupport.addPropertyChangeListener( listener );
        }
    }

    /**
     * Remove a client which had requested notification when an URL
     * is selected
     * @param listener a client to not be notified of changes
     */
    public void removePropertyChangeListener(
                              PropertyChangeListener listener ) {
        if (_propSupport != null) {
            _propSupport.removePropertyChangeListener( listener );
        }
    }

    /**
     * Support for bound property notification
     * @param propName Name of changed property
     * @param oldValue Previous value of property
     * @param newValue New value of property
     */
    public void firePropertyChange( String propName,
                                    Object oldValue,
                                    Object newValue ) {
        if (_propSupport != null) {
            _propSupport.firePropertyChange( propName, oldValue, newValue );
            if (PROPERTY_NAME_URL.equals(propName)) {
                if ( _closeOnSelect ) {
                    _url = (String)newValue;
                    setVisible( false );
                    dispose();
                }
            }
        }
    }
    
  /**
   * Returns <CODE>true</CODE> if a browser is to be launched for
     * the selected help topic. This is always the case, unless the
     * selected URL has a window context specifying that a Java
     * help window be used.
     *
     * @return <CODE>true</CODE> if a browser is to be launched for
     * the selected help topic
     */
    public boolean isBrowserSelected() {
        return _doBrowser;
    }

    /**
     * Instructs dialog to close when a topic is selected
     *
     * @param close <CODE>true</CODE> if the dialog is to close when
     * an URL is selected. Default is <CODE>false</CODE>.
     */
    public void setCloseOnSelect( boolean close ) {
        _closeOnSelect = close;
    }

    /**
     * Reports if dialog will close when a topic is selected
     *
     * @return <CODE>true</CODE> if the dialog is to close when
     * an URL is selected. Default is <CODE>false</CODE>.
     */
    public boolean getCloseOnSelect() {
        return _closeOnSelect;
    }

    protected String getBaseUrl( String baseLine ) {
        int ind = baseLine.indexOf( ' ' );
        int lastInd = baseLine.indexOf( '>' );
        String base = baseLine.substring( ind+1, lastInd );
        lastInd = _indexUrl.lastIndexOf( '/' );
        base = _indexUrl.substring( 0, lastInd+1 ) + base;
        if ( !base.endsWith("/") ) {
            base += '/';
        }
        return base;
    }

    static public void main ( String[] args ) {
        // Parse arguments
        if ( args.length < 1 ) {
            System.err.println( "Usage: IndexDialog url" );
            System.exit( 1 );
        }
       try {
            UIManager.setLookAndFeel(
				"com.netscape.management.nmclf.SuiLookAndFeel" );
	   } catch (Exception e) {
		   Debug.println("Cannot load nmc look and feel.");
		   System.exit(-1);
	   }
       Debug.setTraceLevel( 6 );
       try {
           final IndexDialog dlg = new IndexDialog( null, new URL(args[0]) );
           // Handle property change events when a link is clicked
           dlg.addPropertyChangeListener( new PropertyChangeListener() {
               public void propertyChange(PropertyChangeEvent evt) {
                   if ( evt.getPropertyName().equals( IndexDialog.PROPERTY_NAME_URL ) ) {
                       String url = (String)evt.getNewValue();
                       if ( (url != null) && (url.length() > 0) ) {
                           System.out.println( "Selected URL: " + url );
                           if( dlg.isBrowserSelected() ) {
                               new Browser().open( url, Browser.NEW_WINDOW );
                           } else {
                               new BrowseHtmlDialog(
                                   null, url, true ).showModal();
                           }
                       }
                   }
               }
           } );

           dlg.show();
           // If closeOnSelect was enabled, there is a selected URL
           // now
           String url = dlg.getUrl();
           if ( (url != null) && (url.length() > 0) ) {
               System.out.println( "Selected URL: " + url );
               if( dlg.isBrowserSelected() ) {
                   new Browser().open( url, Browser.NEW_WINDOW );
               } else {
                   new BrowseHtmlDialog( null, url, true ).showModal();
               }
           }
	   } catch (Exception e) {
		   System.err.println("Cannot load " + args[0] + ": " + e);
           e.printStackTrace();
		   System.exit(-1);
	   }
       System.exit( 0 );
    }

    private JEditorPane _pane = null;
    private JTextField _typeInField = null;
    private JList _itemList = null;
    private Hashtable _topics = null;
    private CollationKey[] _keys = null;
    private Collator _collator = Collator.getInstance();
    private String _url = "";
    private String _indexUrl = "";
    private boolean _doBrowser = true;
    private boolean _closeOnSelect = false;
    private PropertyChangeSupport _propSupport =
              new PropertyChangeSupport( this );
    private static final int WIDTH = 400;
    private static final int LIST_HEIGHT = 185;
    private static final int TOPIC_HEIGHT = 100;
    private static final String _section = "IndexDialog";
    public static final String PROPERTY_NAME_URL = "URL";
    private static final ResourceSet _resource =
        new ResourceSet("com.netscape.management.client.util.default");
}
