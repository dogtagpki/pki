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
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var ConnectorModel = Model.extend({
    urlRoot: "/tps/rest/connectors",
    parseResponse: function(response) {
        return {
            id: response.id,
            connectorID: response.id,
            status: response.Status,
            properties: response.Properties
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.connectorID,
            Status: attributes.status,
            Properties: attributes.properties
        };
    },
    changeStatus: function(action, options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?action=" + action,
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    }
});

var ConnectorCollection = Collection.extend({
    urlRoot: "/tps/rest/connectors",
    getEntries: function(response) {
        return response.entries;
    },
    parseEntry: function(entry) {
        return new ConnectorModel({
            id: entry.id,
            status: entry.Status
        });
    }
});

var ConnectorsTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        ConnectorsTable.__super__.initialize.call(self, options);
    },
    add: function() {
        var self = this;

        window.location.hash = "#new-connector";
    }
});

var ConnectorsPage = Page.extend({
    load: function() {
        var self = this;

        var table = new ConnectorsTable({
            el: $("table[name='connectors']"),
            collection: new ConnectorCollection(),
            parent: self
        });

        table.render();
    }
});
