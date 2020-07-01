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

var TPS = {
    PROFILE_ID_PATTERN: /^[a-zA-Z0-9_]+$/,
    PROPERTY_NAME_PATTERN: /^[a-zA-Z0-9_\.]+$/,
    getElementName: function (component) {

        if (component == "Generals") {
            return "config";

        } else if (component == "Authentication_Sources") {
            return "authenticators";

        } else if (component == "Subsystem_Connections") {
            return "connectors";

        } else if (component == "Profiles") {
            return "profiles";

        } else if (component == "Profile_Mappings") {
            return "profile-mappings";

        } else if (component == "Audit_Logging") {
            return "audit";

        } else {
            return null;
        }
    }
};

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
    addEntry: function(entry) {
        var self = this;

        if (!entry.name.match(TPS.PROPERTY_NAME_PATTERN)) {
            throw "Invalid property name: " + entry.name;
        }

        PropertiesTable.__super__.addEntry.call(self, entry);
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

var TPSHomePage = HomePage.extend({
    update: function() {

        TPSHomePage.__super__.update.call(self);

        if (!PKI.user) return;
        var roles = PKI.user.Roles.Role;

        var attributes = PKI.user.Attributes.Attribute;
        var values = PKI.getAttribute(attributes, "components");

        var components;
        if (values) {
            components = values.split(",");
        } else {
            components = [];
        }

        var home_system = self.$("[name=home-system]");
        if (components.length > 0) {
            home_system.show();
            for (var i=0; i<components.length; i++) {
                var name = TPS.getElementName(components[i]);
                if (!name) continue;
                $("[name=" + name + "]", home_system).show();
            }

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

        var roles = PKI.user.Roles.Role;
        var status = self.entry.status;

        if (_.contains(roles, "Administrators") && _.contains(roles, "TPS Agents")) {

            if (status == "Enabled") {
                // admin-agent can disable enabled entries
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.show();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();

            } else if (status == "Disabled") {
                // admin-agent can edit/enable disabled entries
                self.editAction.show();
                self.enableAction.show();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();

            } else if (status == "Pending_Approval") {
                // admin-agent can approve/reject pending entries
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.show();
                self.rejectAction.show();

            } else {
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();
            }

        } else if (_.contains(roles, "Administrators")) {

            if (status == "Disabled") {
                // admin can edit/submit disabled entries
                self.editAction.show();
                self.enableAction.hide();
                self.disableAction.hide();
                self.submitAction.show();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();

            } else if (status == "Pending_Approval") {
                // admin can cancel pending entries
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.show();
                self.approveAction.hide();
                self.rejectAction.hide();

            } else {
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();
            }

        } else if (_.contains(roles, "TPS Agents")) {

            if (status == "Enabled") {
                // agent can disable enabled entries
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.show();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();

            } else if (status == "Disabled") {
                // agent can enable disabled entries
                self.editAction.hide();
                self.enableAction.show();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();

            } else if (status == "Pending_Approval") {
                // agent can approve/reject pending entries
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.show();
                self.rejectAction.show();

            } else {
                self.editAction.hide();
                self.enableAction.hide();
                self.disableAction.hide();
                self.submitAction.hide();
                self.cancelAction.hide();
                self.approveAction.hide();
                self.rejectAction.hide();
            }

        } else {
            self.editAction.hide();
            self.enableAction.hide();
            self.disableAction.hide();
            self.submitAction.hide();
            self.cancelAction.hide();
            self.approveAction.hide();
            self.rejectAction.hide();
        }

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
    saveEntry: function() {
        var self = this;

        if (!self.entry.profileID.match(TPS.PROFILE_ID_PATTERN)) {
            throw "Invalid profile ID: " + self.entry.profileID;
        }

        ConfigEntryPage.__super__.saveEntry.call(self);
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
