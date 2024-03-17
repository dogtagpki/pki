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

import java.util.*;

/**
 * BrowseHtmlPane
 * 
 *
 * @version 1.0
 * @author rweltman
 **/
class BrowseHtmlHistory {
    BrowseHtmlHistory() {
    }

    void setPage( String url ) {
        Debug.println( "BrowseHtmlHistory.setPage: " + url );
        _history.removeAllElements();
        _history.addElement( url );
        _currIndex = 0;
        dumpHistory();
    }

    void addPage( String url ) {
        Debug.println( "BrowseHtmlHistory.addPage: " + url );
        _currIndex++;
        if ( _currIndex >= _history.size() ) {
            _history.addElement( url );
        } else {
            _history.setElementAt( url, _currIndex );
        }
        while( _history.size() > (_currIndex+1) ) {
            _history.removeElementAt( _history.size() - 1 );
        }
        notifyHistoryListeners();
        dumpHistory();
    }

    void previousPage() {
        if ( _currIndex > 0 ) {
            _currIndex--;
            notifyHistoryListeners();
        }
        Debug.println( "BrowseHtmlHistory.previousPage: " + _currIndex );
        dumpHistory();
    }

    void nextPage() {
        if ( _currIndex < (_history.size()-1) ) {
            _currIndex++;
            notifyHistoryListeners();
        }
        Debug.println( "BrowseHtmlHistory.nextPage: " + _currIndex );
        dumpHistory();
    }

    String getCurrentPage() {
        return (String)_history.elementAt( getCurrentIndex() );
    }

    int getCurrentIndex() {
        return _currIndex;
    }

    void notifyHistoryListeners() {
        Debug.println( "BrowseHtmlHistory.notifyHistoryListeners: " +
                       _currIndex + " of " + _history.size() );
        if ( _listener != null ) {
            _listener.historyStateChanged(
                (_currIndex > 0), (_currIndex < (_history.size()-1)) );
        }
    }

    public void addBrowseHistoryListener( BrowseHistoryListener listener ) {
        _listener = listener;
    }

    protected void dumpHistory() {
        Debug.println( "BrowseHtmlHistory.dumpHistory:" );
        for( int i = 0; i < _history.size(); i++ ) {
            Debug.print( (_currIndex == i) ?
                              Integer.toString(i) + "  " : "   " );
            Debug.println( (String)_history.elementAt( i ) );
        }
    }

    private Vector _history = new Vector();
    private int _currIndex = -1;
    private BrowseHistoryListener _listener = null;
}
