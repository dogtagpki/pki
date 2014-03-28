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

var AuthenticatorModel = Model.extend({
    urlRoot: "/tps/rest/authenticators",
    parseResponse: function(response) {
        return {
            id: response.id,
            authenticatorID: response.id,
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

var AuthenticatorCollection = Collection.extend({
    urlRoot: "/tps/rest/authenticators",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new AuthenticatorModel({
            id: entry.id,
            status: entry.Status
        });
    }
});

var AuthenticatorDialog = Dialog.extend({
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
        AuthenticatorDialog.__super__.render.call(self);
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
            AuthenticatorDialog.__super__.performAction.call(self, action);
        }
    }
});

var AuthenticatorsTable = Table.extend({
    initialize: function(options) {
        var self = this;
        AuthenticatorsTable.__super__.initialize.call(self, options);
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

                    var fields = $("div[name='authenticator']", self.container);
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
                        el: $("table[name='authenticator-properties']"),
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

var AuthenticatorsPage = Page.extend({
    load: function(container) {
        var editDialog = new AuthenticatorDialog({
            el: $("#authenticator-dialog"),
            title: "Edit Authenticator",
            readonly: ["id", "status"]
        });

        var table = new AuthenticatorsTable({
            url: "authenticator.html",
            el: $("table[name='authenticators']"),
            collection: new AuthenticatorCollection(),
            editDialog: editDialog,
            container: container
        });
        table.render();
    }
});
