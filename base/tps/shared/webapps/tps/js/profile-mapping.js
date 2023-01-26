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
 * Copyright (C) 2014 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var ProfileMappingModel = Model.extend({
    urlRoot: "/tps/rest/profile-mappings",
    parseResponse: function(response) {
        return {
            id: response.id,
            profileMappingID: response.id,
            status: response.Status,
            properties: response.Properties
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.profileMappingID,
            Status: attributes.status,
            properties: attributes.properties
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

var ProfileMappingCollection = Collection.extend({
    urlRoot: "/tps/rest/profile-mappings",
    getEntries: function(response) {
        return response.entries;
    },
    parseEntry: function(entry) {
        return new ProfileMappingModel({
            id: entry.id,
            status: entry.Status
        });
    }
});

var ProfileMappingsTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        ProfileMappingsTable.__super__.initialize.call(self, options);
    },
    add: function() {
        var self = this;

        window.location.hash = "#new-profile-mapping";
    }
});

var ProfileMappingsPage = Page.extend({
    load: function() {
        var self = this;

        var table = new ProfileMappingsTable({
            el: $("table[name='profile-mappings']"),
            collection: new ProfileMappingCollection(),
            parent: self
        });

        table.render();
    }
});
