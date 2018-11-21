/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2018 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var KeyRequestModel = Model.extend({
    urlRoot: "/kra/rest/agent/keyrequests",
    parseResponse: function(response) {
        var requestURL = response.requestURL;
        var i = requestURL.lastIndexOf('/');
        var keyURL = response.keyURL;
        var j = keyURL.lastIndexOf('/');
        return {
            id: requestURL.substring(i + 1),
            type: response.requestType,
            status: response.requestStatus,
            keyId: keyURL.substring(j + 1),
        };
    }
});

var KeyRequestCollection = Collection.extend({
    urlRoot: "/kra/rest/agent/keyrequests",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        var requestURL = entry.requestURL;
        var i = requestURL.lastIndexOf('/');
        var keyURL = entry.keyURL;
        var j = keyURL.lastIndexOf('/');
        return new KeyRequestModel({
            id: requestURL.substring(i + 1),
            type: entry.requestType,
            status: entry.requestStatus,
            keyId: keyURL.substring(j + 1),
        });
    }
});

var KeyRequestPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        KeyRequestPage.__super__.initialize.call(self, options);
    }
});

var KeyRequestsTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        KeyRequestsTable.__super__.initialize.call(self, options);
    }
});

var KeyRequestsPage = Page.extend({
    load: function() {
        var self = this;

        var table = new KeyRequestsTable({
            el: $("table[name='keyrequests']"),
            collection: self.collection
        });

        table.render();
    }
});
