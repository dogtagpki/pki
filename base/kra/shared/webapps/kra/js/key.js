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

var KeyModel = Model.extend({
    urlRoot: "/kra/rest/agent/keys",
    parseResponse: function(response) {
        var i = response.keyURL.lastIndexOf('/');
        var id = response.keyURL.substring(i + 1);
        return {
            id: id,
            algorithm: response.algorithm,
            size: response.size,
            ownerName: response.ownerName,
            publicKey: response.publicKey,
        };
    }
});

var KeyCollection = Collection.extend({
    urlRoot: "/kra/rest/agent/keys",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        var i = entry.keyURL.lastIndexOf('/');
        var id = entry.keyURL.substring(i + 1);
        return new KeyModel({
            id: id,
            algorithm: entry.algorithm,
            size: entry.size,
            ownerName: entry.ownerName
        });
    }
});

var KeyPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        KeyPage.__super__.initialize.call(self, options);
    }
});

var KeysTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        KeysTable.__super__.initialize.call(self, options);
    }
});

var KeysPage = Page.extend({
    load: function() {
        var self = this;

        var table = new KeysTable({
            el: $("table[name='keys']"),
            collection: self.collection
        });

        table.render();
    }
});
