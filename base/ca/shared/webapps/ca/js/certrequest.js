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

var CertRequestModel = Model.extend({
    urlRoot: "/ca/rest/certrequests",
    parseResponse: function(response) {
        var url = response.requestURL;
        var i = url.lastIndexOf('/');
        return {
            id: url.substring(i + 1),
            type: response.requestType,
            status: response.requestStatus,
            certRequestType: response.certRequestType,
            certId: response.certId,
            operationResult: response.operationResult,
        };
    }
});

var CertRequestCollection = Collection.extend({
    urlRoot: "/ca/rest/agent/certrequests",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        var url = entry.requestURL;
        var i = url.lastIndexOf('/');
        return new CertRequestModel({
            id: url.substring(i + 1),
            type: entry.requestType,
            status: entry.requestStatus,
            certRequestType: entry.certRequestType,
            certId: entry.certId,
            operationResult: entry.operationResult,
        });
    }
});

var CertRequestPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        CertRequestPage.__super__.initialize.call(self, options);
    }
});

var CertRequestsTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        CertRequestsTable.__super__.initialize.call(self, options);
    }
});

var CertRequestsPage = Page.extend({
    load: function() {
        var self = this;

        var table = new CertRequestsTable({
            el: $("table[name='certrequests']"),
            collection: self.collection
        });

        table.render();
    }
});
