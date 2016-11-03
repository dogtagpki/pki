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
        var self = this;
        self.update();
    },
    update: function() {
        if (!tps.user) return;
        var roles = tps.user.Roles.Role;
        var home_accounts = self.$("[name=home-accounts]");
        var home_system = self.$("[name=home-system]");

        if (_.contains(roles, "Administrators")) {
            home_accounts.show();
        } else {
            home_accounts.hide();
        }

        if (_.contains(roles, "Administrators")) {
            home_system.show();
            $("li", home_system).show();

        } else if (_.contains(roles, "TPS Agents")) {
            home_system.show();
            $("li", home_system).hide();
            $("[name=profiles]", home_system).show();

        } else {
            home_system.hide();
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

        self.submitAction = $("[name='submit']", self.viewMenu);
        self.cancelAction = $("[name='cancel']", self.viewMenu);
        self.approveAction = $("[name='approve']", self.viewMenu);
        self.rejectAction = $("[name='reject']", self.viewMenu);
        self.enableAction = $("[name='enable']", self.viewMenu);
        self.disableAction = $("[name='disable']", self.viewMenu);

        $("a", self.submitAction).click(function(e) {
            e.preventDefault();
            self.changeStatus("submit", "Are you sure you want to submit this entry?");
        });

        $("a", self.cancelAction).click(function(e) {
            e.preventDefault();
            self.changeStatus("cancel", "Are you sure you want to cancel this entry?");
        });

        $("a", self.approveAction).click(function(e) {
            e.preventDefault();
            self.changeStatus("approve", "Are you sure you want to approve this entry?");
        });

        $("a", self.rejectAction).click(function(e) {
            e.preventDefault();
            self.changeStatus("reject", "Are you sure you want to reject this entry?");
        });

        $("a", self.enableAction).click(function(e) {
            e.preventDefault();
            self.changeStatus("enable", "Are you sure you want to enable this entry?");
        });

        $("a", self.disableAction).click(function(e) {
            e.preventDefault();
            self.changeStatus("disable", "Are you sure you want to disable this entry?");
        });

        var dialog = self.$("#property-dialog");

        var addDialog = new Dialog({
            el: dialog,
            title: "Add Property",
            actions: ["cancel", "add"]
        });

        var propertiesSection = self.$("[name='properties']");
        self.propertiesList = $("[name='list']", propertiesSection);
        self.propertiesEditor = $("[name='editor']", propertiesSection);
        self.propertiesTextarea = $("textarea", self.propertiesEditor);

        self.propertiesTable = new PropertiesTable({
            el: self.propertiesList,
            addDialog: addDialog,
            tableItem: self.tableItem,
            pageSize: self.tableSize,
            parent: self
        });

        $("[name='showEditor']", propertiesSection).click(function(e) {

            var properties = self.getProperties();
            self.setProperties(properties);

            self.propertiesList.hide();
            self.propertiesEditor.show();
        });

        $("[name='showList']", propertiesSection).click(function(e) {

            var properties = self.getProperties();
            self.setProperties(properties);

            self.propertiesList.show();
            self.propertiesEditor.hide();
        });
    },
    renderContent: function() {
        var self = this;

        ConfigEntryPage.__super__.renderContent.call(self);

        var status = self.entry.status;
        if (status == "Disabled") {
            self.editAction.show();
            self.enableAction.show();
            self.disableAction.hide();

        } else {
            self.editAction.hide();
            self.enableAction.hide();
            self.disableAction.show();
        }

        self.submitAction.hide();
        self.cancelAction.hide();
        self.approveAction.hide();
        self.rejectAction.hide();

        if (self.mode == "add") {
            self.propertiesTable.mode = "edit";
            self.propertiesTextarea.removeAttr("readonly");
            self.setProperties([]);

        } else if (self.mode == "edit") {
            self.propertiesTable.mode = "edit";
            self.propertiesTextarea.removeAttr("readonly");
            self.setProperties(self.entry.properties);

        } else { // self.mode == "view"
            self.propertiesTable.mode = "view";
            self.propertiesTextarea.attr("readonly", "readonly");
            self.setProperties(self.entry.properties);
        }
    },
    saveFields: function() {
        var self = this;

        ConfigEntryPage.__super__.saveFields.call(self);

        self.entry.properties = self.getProperties();
    },
    setProperties: function(properties) {
        var self = this;

        self.propertiesTable.entries = properties;
        self.propertiesTable.render();

        var text = "";
        _.each(properties, function(property) {
            var name = property.name;
            var value = property.value;
            text += name + "=" + value + "\n";
        });
        self.propertiesTextarea.val(text);
    },
    getProperties: function() {
        var self = this;

        if (self.propertiesList.is(":visible")) {
            return self.propertiesTable.entries;

        } else {
            var properties = [];

            var lines = self.propertiesTextarea.val().split("\n");
            _.each(lines, function(line) {
                var match = /^([^=]+)=(.*)$/.exec(line);
                if (!match) return;

                var name = match[1];
                var value = match[2];

                var property = {};
                property["name"] = name;
                property["value"] = value;

                properties.push(property);
            });

            return properties;
        }
    }
});
