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

var ConnectionModel = Model.extend({
    urlRoot: "/tps/rest/connections",
    parseResponse: function(response) {
        return {
            id: response.id,
            connectionID: response.id,
            status: response.Status,
            properties: response.Properties.Property
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.profileID,
            Status: attributes.status,
            Properties: {
                Property: attributes.properties
            }
        };
    },
    enable: function(options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?action=enable",
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    },
    disable: function(options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "?action=disable",
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            self.set(self.parseResponse(data));
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    }
});

var ConnectionCollection = Collection.extend({
    urlRoot: "/tps/rest/connections",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new ConnectionModel({
            id: entry.id,
            status: entry.Status
        });
    }
});

var ConnectionDialog = Dialog.extend({
    render: function() {
        var self = this;
        var status = self.model.get("status");
        if (status == "Enabled") {
            self.actions = ["disable", "cancel"];
        } else if (status == "Disabled") {
            self.actions = ["enable", "cancel"];
        } else {
            alert("ERROR: Invalid status: " + status);
        }
        ConnectionDialog.__super__.render.call(self);
    },
    performAction: function(action) {
        var self = this;

        if (action == "enable") {
            self.model.enable({
                success: function(data,textStatus, jqXHR) {
                    self.close();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert("ERROR: " + textStatus);
                }
            });

        } else if (action == "disable") {
            self.model.disable({
                success: function(data,textStatus, jqXHR) {
                    self.close();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert("ERROR: " + textStatus);
                }
            });

        } else {
            ConnectionDialog.__super__.performAction.call(self, action);
        }
    }
});

var ConnectionsTable = Table.extend({
    initialize: function(options) {
        var self = this;
        ConnectionsTable.__super__.initialize.call(self, options);
        self.url = options.url;
        self.container = options.container;
    },
    open: function(item) {
        var self = this;

        // load entry properties
        item.model.fetch({
            success: function(model, response, options) {
                self.container.load(self.url, function(response, status, xhr) {
                    $("h1 span[name='id']", self.container).text(model.id);

                    var fields = $("div[name='connection']", self.container);
                    $("input[name='id']", fields).val(model.id);
                    $("input[name='status']", fields).val(model.get("status"));

                    var dialog = $("#property-dialog");

                    var addDialog = new Dialog({
                        el: dialog,
                        title: "Add Property",
                        actions: ["cancel", "add"]
                    });

                    var editDialog = new Dialog({
                        el: dialog,
                        title: "Edit Property",
                        readonly: ["name"],
                        actions: ["cancel", "save"]
                    });

                    var properties = new PropertiesTable({
                        el: $("table[name='connection-properties']"),
                        properties: model.get("properties"),
                        addDialog: addDialog,
                        editDialog: editDialog,
                        pageSize: 10
                    });
                    properties.render();
                });
            }
        });
    }
});

var ConnectionsPage = Page.extend({
    load: function(container) {
        var editDialog = new ConnectionDialog({
            el: $("#connection-dialog"),
            title: "Edit Connection",
            readonly: ["id", "status"]
        });

        var table = new ConnectionsTable({
            url: "connection.html",
            el: $("table[name='connections']"),
            collection: new ConnectionCollection(),
            editDialog: editDialog,
            container: container
        });
        table.render();
    }
});
