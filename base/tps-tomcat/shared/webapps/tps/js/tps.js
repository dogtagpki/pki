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

var EntryWithPropertiesPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        EntryWithPropertiesPage.__super__.initialize.call(self, options);
        self.parentPage = options.parentPage;
        self.tableItem = options.tableItem;
        self.tableSize = options.tableSize || 10;
    },
    setup: function() {
        var self = this;

        EntryWithPropertiesPage.__super__.setup.call(self);

        self.enableLink = $("a[name='enable']", self.menu);
        self.disableLink = $("a[name='disable']", self.menu);

        self.enableLink.click(function(e) {
            var message = "Are you sure you want to enable this entry?";
            if (!confirm(message)) return;
            self.model.enable({
                success: function(data, textStatus, jqXHR) {
                    self.attributes = _.clone(self.model.attributes);
                    self.render();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert("ERROR: " + textStatus);
                }
            });
        });

        self.disableLink.click(function(e) {
            var message = "Are you sure you want to disable this entry?";
            if (!confirm(message)) return;
            self.model.disable({
                success: function(data, textStatus, jqXHR) {
                    self.attributes = _.clone(self.model.attributes);
                    self.render();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert("ERROR: " + textStatus);
                }
            });
        });

        var dialog = self.$("#property-dialog");

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

        var viewDialog = new Dialog({
            el: dialog,
            title: "Property",
            readonly: ["name", "value"],
            actions: ["close"]
        });

        var table = self.$("table[name='properties']");
        self.addButton = $("button[name='add']", table);
        self.removeButton = $("button[name='remove']", table);

        self.propertiesTable = new PropertiesTable({
            el: table,
            addDialog: addDialog,
            editDialog: editDialog,
            viewDialog: viewDialog,
            tableItem: self.tableItem,
            pageSize: self.tableSize
        });
    },
    renderContent: function() {
        var self = this;

        EntryWithPropertiesPage.__super__.renderContent.call(self);

        var status = self.attributes.status;
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
            self.propertiesTable.entries = self.attributes.properties;

        } else { // self.mode == "view"
            self.propertiesTable.mode = "view";
            self.propertiesTable.entries = self.attributes.properties;
        }

        self.propertiesTable.render();
    },
    saveFields: function() {
        var self = this;

        EntryWithPropertiesPage.__super__.saveFields.call(self);

        self.attributes.properties = self.propertiesTable.entries;
    },
    close: function() {
        var self = this;
        if (self.parentPage) {
            self.parentPage.open();
        } else {
            EntryWithPropertiesPage.__super__.close.call(self);
        }
    }
});
