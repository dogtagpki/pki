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

import java.awt.*;
import java.awt.event.*;
import java.net.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.text.*;
import javax.swing.text.html.*;
import com.netscape.management.nmclf.SuiConstants;

/**
 * Dialog to host a BrowseHtmlPane (HTML help)
 *
 * @version 1.0
 * @author rweltman
 **/
public class BrowseHtmlDialog extends AbstractDialog
                              implements BrowseHistoryListener,
                                         ActionListener,
                                         HyperlinkListener {
    public BrowseHtmlDialog( Frame frame,
                             String url,
                             boolean doBrowser ) {
        super( frame );
        _doBrowser = doBrowser;
        prepareContentPane( url, doBrowser );
        setDefaultCloseOperation( DISPOSE_ON_CLOSE );
        pack();
    }

    protected void prepareContentPane( String url, boolean doBrowser ) {
        _pane = new BrowseHtmlPane( url );
        monitorTitle( _pane );
        _pane.addHyperlinkListener( this );
        JScrollPane sp = new JScrollPane( _pane );
        _contentPane = new JPanel();
        _contentPane.setLayout( new BorderLayout() );
        _contentPane.setBorder( UIManager.getBorder( "TextField.border" ) );
        _contentPane.add( sp, BorderLayout.CENTER );
        Dimension dim = new Dimension( 600, 450 );
        _contentPane.setMinimumSize( dim );
        _contentPane.setPreferredSize( dim );
        setContentPane( _contentPane );
        if ( doBrowser ) {
        } else {
            addNavigationPanel( url );
        }
        // Cause title and navigation buttons to be updated
        historyStateChanged( false, false );
        // Track Shift and Control key states, to override navigation
        // embedded in URLs
        _pane.addKeyListener( new KeyAdapter() {
            public void keyPressed( KeyEvent e ) {
                switch( e.getKeyCode() ) {
                case KeyEvent.VK_SHIFT:
                    _defaultWindowContext = WC_SAMEWINDOW;
                    break;
                case KeyEvent.VK_CONTROL:
                    _defaultWindowContext = WC_NEWWINDOW;
                    break;
                }
            }
            public void keyReleased( KeyEvent e ) {
                switch( e.getKeyCode() ) {
                case KeyEvent.VK_SHIFT:
                    if ( _defaultWindowContext == WC_SAMEWINDOW ) {
                        _defaultWindowContext = WC_NOCONTEXT;
                    }
                    break;
                case KeyEvent.VK_CONTROL:
                    if ( _defaultWindowContext == WC_NEWWINDOW ) {
                        _defaultWindowContext = WC_NOCONTEXT;
                    }
                    break;
                }
            }
        } );
    }

    protected void addNavigationPanel( String url ) {
        if ( hasNavigationPanel() ) {
            return;
        }
        _history = new BrowseHtmlHistory();
        _history.addBrowseHistoryListener( this );
        _history.setPage( url );
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        buttonPanel.setBorder(
            new EmptyBorder(SuiConstants.VERT_WINDOW_INSET,
                            SuiConstants.HORIZ_WINDOW_INSET,
                            SuiConstants.VERT_WINDOW_INSET,
                            SuiConstants.HORIZ_WINDOW_INSET));
        _backButton = JButtonFactory.create(
            _resource.getString(null, "BackButtonLabel"), this, "BACK");
        buttonPanel.add( _backButton );
        buttonPanel.add( Box.createRigidArea(
            new Dimension(SuiConstants.COMPONENT_SPACE, 0)));
        _nextButton = JButtonFactory.create(
            _resource.getString(null, "ForwardButtonLabel"), this,
            "FORWARD");
        buttonPanel.add( _nextButton );
        JButtonFactory.resizeGroup(_nextButton, _backButton);
        _contentPane.add( buttonPanel, BorderLayout.SOUTH );
        invalidate();
        validate();
    }

    /**
     * Extract a URL parameter
     *
     * @param url the complete URL
     * @param key the parameter to extract
     * @return the value of the parameter, or <CODE>null</CODE>
     * if not present
     */
    static String getUrlParameter( String url, String key ) {
        String token = '?' + key + '=';
        int ind = url.indexOf( token );
        if ( ind < 0 ) {
            token = '&' + key + '=';
            ind = url.indexOf( token );
        }
        if ( ind < 0 ) {
            return null;
        }
        url = url.substring( ind + token.length() );
        int end = url.indexOf( '&' );
        if ( end == -1 ) {
            end = url.length();
        }
        return url.substring( 0, end );
    }

    /**
     * Determine if a URL specifies a window context
     *
     * @param url the complete URL
     * @return the window context in the URL (WC_NOCONTEXT if none)
     */
    static int getWindowContext( String url ) {
        String contextString = getUrlParameter( url, WC_KEY );
        int context = WC_NOCONTEXT;
        if ( contextString != null ) {
            if ( contextString.equals( WC_NEWWINDOW_STRING ) ) {
                context = WC_NEWWINDOW;
            } else if ( contextString.equals( WC_SAMEWINDOW_STRING ) ) {
                context = WC_SAMEWINDOW;
            } else if ( contextString.equals( WC_BROWSER_STRING ) ) {
                context = WC_BROWSER;
            }
        }
        return context;
    }

    /**
     * Called when a hyperlink is clicked in the HTML window; calls
     * hyperLinkUpdate(e, true) to update the HTML window or launch
     * a browser.
     *
     * @param e event containing URL info
     */
    public void hyperlinkUpdate( HyperlinkEvent e ) {
        hyperlinkUpdate( e, true );
    }

    protected void hyperlinkUpdate( HyperlinkEvent e, boolean update ) {
        if ( e.getEventType() == HyperlinkEvent.EventType.ACTIVATED ) {
            String url = e.getURL().toString();
            BrowseHtmlPane pane = (BrowseHtmlPane)e.getSource();
            if ( e instanceof HTMLFrameHyperlinkEvent ) {
                Debug.println( "Frame event for URL " + e.getURL() );
                HTMLFrameHyperlinkEvent  evt = (HTMLFrameHyperlinkEvent)e;
                HTMLDocument doc = (HTMLDocument)pane.getDocument();
                doc.processHTMLFrameHyperlinkEvent( evt );
            } else {
                try {
                    Debug.println( "Setting the URL to " + e.getURL() );
                    // Refresh the window if Shift is pressed, launch
                    // a new one if Control is pressed; otherwise go
                    // by what is in the window context parameter of the
                    // URL. Default: launch the browser. If the dialog
                    // already has navigation buttons, just refresh.
                    int wc = ( _defaultWindowContext != WC_NOCONTEXT ) ?
                        _defaultWindowContext : (hasNavigationPanel()) ?
                        WC_SAMEWINDOW : getWindowContext( url );
                    Debug.println( "Window context: " + wc );
                    if ( wc == WC_NOCONTEXT ) {
                        wc = WC_BROWSER;
                    }
                    // Based on the optional presence of a window context
                    // parameter in the URL, launch a browser, refresh
                    // the window, or launch a new window
                    switch( wc ) {
                    case WC_SAMEWINDOW:
                        addNavigationPanel( pane.getPage().toString() );
                        if ( update ) {
                            _history.addPage( url );
                        }
                        pane.setPage( url );
                        monitorTitle( pane );
                        break;
                    case WC_NEWWINDOW:
                        new BrowseHtmlDialog( null, url, _doBrowser );
                        break;
                    case WC_BROWSER:
                        new Browser("Help").open( url,Browser.NEW_WINDOW );
                        break;
                    }
                } catch (Throwable t) {
                    t.printStackTrace();
                }
            }
        }
    }

    /**
     * Move the pointer in the history list back if possible, and
     * update the HTML window
     */
    public void previousPage() {
        _history.previousPage();
        updateFromIndex();
    }

    /**
     * Advance the pointer in the history list if possible, and
     * update the HTML window
     */
    public void nextPage() {
        _history.nextPage();
        updateFromIndex();
    }

    protected void updateFromIndex() {
        String currUrl = _history.getCurrentPage();
        try {
            hyperlinkUpdate( new HyperlinkEvent(
                _pane, HyperlinkEvent.EventType.ACTIVATED,
                new URL(currUrl), currUrl ), false );
        } catch ( MalformedURLException ex ) {
            System.err.println( currUrl + ": " + ex );
            _pane.setText( currUrl + ": " + ex );
        }
    }

    /**
     * Center the dialog on the screen
     */
    protected void center() {
        Dimension screenSize =
            Toolkit.getDefaultToolkit().getScreenSize();
        Dimension size = getSize();
        screenSize.height = screenSize.height/2;
        screenSize.width = screenSize.width/2;
        size.height = size.height/2;
        size.width = size.width/2;
        int y = screenSize.height - size.height;
        int x = screenSize.width - size.width;
        setLocation(x, y);
    }

    public void actionPerformed( ActionEvent e ) {
        if ( e.getActionCommand().equals( "BACK" ) ) {
            previousPage();
        } else if ( e.getActionCommand().equals( "FORWARD" ) ) {
            nextPage();
        }
    }

    /**
     * Called when the history list for the window changes; updates
     * the state of the navigation buttons (enabled or disabled)
     *
     * @param previous <code>true if there is a previous entry in the
     * history list
     * @param next <code>true if there is a next entry in the
     * history list
     */
    public void historyStateChanged( boolean previous, boolean next ) {
        if ( _backButton != null ) {
            _nextButton.setEnabled( next );
            _backButton.setEnabled( previous );
        }
    }

    /**
     * Watch for the title of a JEditorPane and set it as the dialog
     * title
     *
     * @param pane a JEditorPane
     */
    protected void monitorTitle( JEditorPane pane ) {
        // If the title has already been parsed into the document,
        // get it here
        String title =
            (String)pane.getDocument().getProperty( Document.TitleProperty );
        if( title != null ) {
            setTitle( title );
            return;
        }
        // The title is not yet available, so watch for its appearance
        // as the document is parsed
        DocumentListener l = new DocumentListener() {
            public void changedUpdate( DocumentEvent e ) {
            }
            public void removeUpdate( DocumentEvent e ) {
            }
            public void insertUpdate( DocumentEvent e ) {
                Document d = e.getDocument();
                String t =
                    (String)d.getProperty( Document.TitleProperty );
                if( t != null ) {
                    Debug.println( "BrowseHtmlDialog.monitorTitle: document " +
                                   "title = <" + t + ">" );
                    setTitle( t );
                    d.removeDocumentListener( this );
                }
            }
        };
        pane.getDocument().addDocumentListener( l );
        // The TITLE tag may already have been parsed
        title =
            (String)pane.getDocument().getProperty( Document.TitleProperty );
        if( title != null ) {
            setTitle( title );
            pane.getDocument().removeDocumentListener( l );
        }
    }

    protected boolean hasNavigationPanel() {
        return ( _backButton != null );
    }

    static public void main ( String[] args ) {
        // Parse arguments
        if ( args.length < 1 ) {
            System.err.println( "Usage: BrowseHtmlPane URL [-browser]" );
            System.exit( 1 );
        }
        boolean doBrowser = ( (args.length > 1) &&
                              args[1].equals("-browser") );
        String currUrl = args[0];
        new BrowseHtmlDialog( null, currUrl, doBrowser ).show();
    }

    static final int WC_BROWSER = 0;
    static final int WC_NEWWINDOW = 1;
    static final int WC_SAMEWINDOW = 2;
    static final int WC_NOCONTEXT = -1;
    private int _context = WC_BROWSER;
    static final String WC_KEY = "windowcontext";
    static final String WC_BROWSER_STRING = "browser";
    static final String WC_NEWWINDOW_STRING = "newwindow";
    static final String WC_SAMEWINDOW_STRING = "samewindow";
    private BrowseHtmlPane _pane = null;
    private BrowseHtmlHistory _history = null;
    private JPanel _contentPane = null;
    private boolean _doBrowser;
    private JButton _backButton = null;
    private JButton _nextButton = null;
    private int _defaultWindowContext = WC_NOCONTEXT;
    private static ResourceSet _resource =
        new ResourceSet("com.netscape.management.client.util.default");
}
