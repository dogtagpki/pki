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
            status: response.Status
        };
    },
    parseXML: function(data) {
        var xml = $(data);
        var entry = $("Authenticator", xml);
        var status = $("Status", entry);
        return {
            id: entry.attr("id"),
            status: status.text()
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.id,
            Status: attributes.status
        };
    },
    enable: function(options) {
        var self = this;
        $.post(self.url() + "?action=enable")
            .done(function(data, textStatus, jqXHR) {
                self.set(self.parseXML(data));
                options.success.call(self, data, textStatus, jqXHR);
            })
            .fail(function(jqXHR, textStatus, errorThrown) {
                options.error.call(self, jqXHR, textStatus, errorThrown);
            });
    },
    disable: function(options) {
        var self = this;
        $.post(self.url() + "?action=disable")
            .done(function(data, textStatus, jqXHR) {
                self.set(self.parseXML(data));
                options.success.call(self, data, textStatus, jqXHR);
            })
            .fail(function(jqXHR, textStatus, errorThrown) {
                options.error.call(self, jqXHR, textStatus, errorThrown);
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

var AuthenticatorPage = Page.extend({
    load: function() {
        var editDialog = new AuthenticatorDialog({
            el: $("#authenticator-dialog"),
            title: "Edit Authenticator",
            readonly: ["id", "status"]
        });

        new Table({
            el: $("table[name='authenticators']"),
            collection: new AuthenticatorCollection({ size: 3 }),
            editDialog: editDialog
        });
    }
});
