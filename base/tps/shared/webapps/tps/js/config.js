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

var ConfigModel = Model.extend({
    url: function() {
        return "/tps/rest/config";
    },
    parseResponse: function(response) {
        return {
            id: "config",
            status: response.Status,
            properties: response.Properties.Property
        };
    },
    createRequest: function(entry) {
        return {
            Status: entry.status,
            Properties: {
                Property: entry.properties
            }
        };
    }
});

var ConfigPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        options.model = new ConfigModel();
        ConfigPage.__super__.initialize.call(self, options);
        self.tableItem = options.tableItem || PropertiesTableItem;
        self.tableSize = options.tableSize || 15;
    },
    setup: function() {
        var self = this;

        ConfigPage.__super__.setup.call(self);

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

        ConfigPage.__super__.renderContent.call(self);

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

        ConfigPage.__super__.saveFields.call(self);

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
