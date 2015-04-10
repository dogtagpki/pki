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

var tps = {};

var PropertiesTableItem = TableItem.extend({
    initialize: function(options) {
        var self = this;
        PropertiesTableItem.__super__.initialize.call(self, options);
    },
    get: function(name) {
        var self = this;

        if (name.substring(0, 7) == "parent.") {
            name = name.substring(7);
            return self.table.parent.entry[name];
        }

        return PropertiesTableItem.__super__.get.call(self, name);
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        PropertiesTableItem.__super__.renderColumn.call(self, td, templateTD);

        $("a", td).click(function(e) {
            e.preventDefault();
            self.open();
        });
    },
    open: function() {
        var self = this;

        var dialog;

        if (self.table.mode == "view") {
            // In view mode all properties are read-only.
            dialog = new Dialog({
                el: self.table.parent.$("#property-dialog"),
                title: "Property",
                readonly: ["name", "value"],
                actions: ["close"]
            });

        } else {
            // In edit mode all properties are editable.
            dialog = new Dialog({
                el: self.table.parent.$("#property-dialog"),
                title: "Edit Property",
                readonly: ["name"],
                actions: ["cancel", "save"]
            });

            dialog.handler("save", function() {

                // save changes
                dialog.save();
                _.extend(self.entry, dialog.entry);

                // redraw table
                self.table.render();
                dialog.close();
            });
        }

        dialog.entry = _.clone(self.entry);

        dialog.open();
    }
});

var PropertiesTable = Table.extend({
    initialize: function(options) {
        var self = this;
        options.columnMappings = {
            id: "name"
        };
        PropertiesTable.__super__.initialize.call(self, options);
    },
    sort: function() {
        var self = this;

        // sort properties by name
        self.filteredEntries = _.sortBy(self.filteredEntries, function(entry) {
            return entry.name;
        });
    },
    remove: function(items) {
        var self = this;

        // remove selected entries
        self.entries = _.reject(self.entries, function(entry) {
            return _.contains(items, entry.name);
        });

        // redraw table
        self.render();
    }
});

var HomePage = Page.extend({
    load: function() {
        var roles = tps.user.Roles.Role;
        var home_accounts = self.$("[name=home-accounts]");
        var home_system = self.$("[name=home-system]");

        if (_.contains(roles, "Administrators")) {
            home_accounts.show();
            $("li", home_system).show();

        } else if (_.contains(roles, "TPS Agents")) {
            home_accounts.hide();
            $("li", home_system).hide();
            $("[name=profiles]", home_system).show();
        }
    }
});

var ConfigEntryPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        ConfigEntryPage.__super__.initialize.call(self, options);
        self.tableItem = options.tableItem || PropertiesTableItem;
        self.tableSize = options.tableSize || 10;
    },
    setup: function() {
        var self = this;

        ConfigEntryPage.__super__.setup.call(self);

        self.enableLink = $("a[name='enable']", self.viewMenu);
        self.disableLink = $("a[name='disable']", self.viewMenu);

        self.enableLink.click(function(e) {

            e.preventDefault();

            var message = "Are you sure you want to enable this entry?";
            if (!confirm(message)) return;
            self.model.enable({
                success: function(data, textStatus, jqXHR) {
                    self.entry = _.clone(self.model.attributes);
                    self.render();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + jqXHR.responseJSON.Code,
                        content: jqXHR.responseJSON.Message
                    }).open();
                }
            });
        });

        self.disableLink.click(function(e) {

            e.preventDefault();

            var message = "Are you sure you want to disable this entry?";
            if (!confirm(message)) return;
            self.model.disable({
                success: function(data, textStatus, jqXHR) {
                    self.entry = _.clone(self.model.attributes);
                    self.render();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + jqXHR.responseJSON.Code,
                        content: jqXHR.responseJSON.Message
                    }).open();
                }
            });
        });

        var dialog = self.$("#property-dialog");

        var addDialog = new Dialog({
            el: dialog,
            title: "Add Property",
            actions: ["cancel", "add"]
        });

        var table = self.$("table[name='properties']");
        self.addButton = $("button[name='add']", table);
        self.removeButton = $("button[name='remove']", table);

        self.propertiesTable = new PropertiesTable({
            el: table,
            addDialog: addDialog,
            tableItem: self.tableItem,
            pageSize: self.tableSize,
            parent: self
        });
    },
    renderContent: function() {
        var self = this;

        ConfigEntryPage.__super__.renderContent.call(self);

        var status = self.entry.status;
        if (status == "Disabled") {
            self.enableLink.show();
            self.disableLink.hide();

        } else if (status == "Enabled") {
            self.enableLink.hide();
            self.disableLink.show();
        }

        if (self.mode == "add") {
            self.propertiesTable.mode = "edit";
            self.propertiesTable.entries = [];

        } else if (self.mode == "edit") {
            self.propertiesTable.mode = "edit";
            self.propertiesTable.entries = self.entry.properties;

        } else { // self.mode == "view"
            self.propertiesTable.mode = "view";
            self.propertiesTable.entries = self.entry.properties;
        }

        self.propertiesTable.render();
    },
    saveFields: function() {
        var self = this;

        ConfigEntryPage.__super__.saveFields.call(self);

        self.entry.properties = self.propertiesTable.entries;
    }
});
