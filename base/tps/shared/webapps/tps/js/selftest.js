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

var SelfTestModel = Model.extend({
    urlRoot: "/tps/rest/selftests",
    parseResponse: function(response) {
        return {
            id: response.id,
            enabledAtStartup: response.EnabledAtStartup,
            criticalAtStartup: response.CriticalAtStartup,
            enabledOnDemand: response.EnabledOnDemand,
            criticalOnDemand: response.CriticalOnDemand,
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.id,
            EnabledAtStartup: attributes.enabledAtStartup,
            CriticalAtStartup: attributes.criticalAtStartup,
            EnabledOnDemand: attributes.enabledOnDemand,
            CriticalOnDemand: attributes.criticalOnDemand
        };
    },
    run: function(options) {
        var self = this;
        $.ajax({
            type: "POST",
            url: self.url() + "/run",
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    }
});

var SelfTestCollection = Collection.extend({
    urlRoot: "/tps/rest/selftests",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new SelfTestModel({
            id: entry.id,
            enabledAtStartup: entry.EnabledAtStartup,
            criticalAtStartup: entry.CriticalAtStartup,
            enabledOnDemand: entry.EnabledOnDemand,
            criticalOnDemand: entry.CriticalOnDemand,
        });
    }
});

var SelfTestPage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        SelfTestPage.__super__.initialize.call(self, options);
    },
    setup: function() {
        var self = this;

        SelfTestPage.__super__.setup.call(self);

        self.runAction = $("[name='run']", self.viewMenu);

        $("a", self.runAction).click(function(e) {

            e.preventDefault();

            self.model.run({
                success: function(data, textStatus, jqXHR) {
                    self.showResult({
                        id: data.id,
                        status: data.Status,
                        output: data.Output
                    });
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    self.showResult({
                        id: self.model.get("id"),
                        status: textStatus,
                        output: errorThrown
                    });
                }
            });

        });
    },
    showResult: function(data) {
        var dialog = new Dialog({
            el: self.$("#selftest-result-dialog"),
            title: "Self Test Result",
            readonly: ["id", "status", "output"],
            actions: ["close"]
        });

        dialog.entry = data;

        dialog.open();
    }
});

var SelfTestsTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        SelfTestsTable.__super__.initialize.call(self, options);

        self.runButton = $("[name='run']", self.buttons);
        self.runButton.click(function(e) {
            var items = self.getSelectedRows();
            _.each(items, function(item, index) {
                self.runTest(item, index);
            });
        });

        self.clearButton = $("[name='clear']", self.buttons);
        self.clearButton.click(function(e) {
            var items = self.getSelectedRows();
            _.each(items, function(item, index) {
                self.clearTest(item, index);
            });
        });
    },
    runTest: function(item, index) {
        var self = this;

        var statusTD = $("td[name='status']", item.$el);
        statusTD.text("RUNNING");

        var id = item.get("id");
        var model = self.collection.get(id);

        model.run({
            success: function(data, textStatus, jqXHR) {
                statusTD.empty();
                var link = $("<a/>", {
                    text: data.Status,
                    click: function(e) {
                        e.preventDefault();
                        self.showResult({
                            id: data.id,
                            status: data.Status,
                            output: data.Output
                        });
                    }
                }).appendTo(statusTD);
            },
            error: function(jqXHR, textStatus, errorThrown) {
                statusTD.empty();
                var link = $("<a/>", {
                    text: textStatus,
                    click: function(e) {
                        e.preventDefault();
                        self.showResult({
                            id: id,
                            status: textStatus,
                            output: errorThrown
                        });
                    }
                }).appendTo(statusTD);
            }
        });
    },
    clearTest: function(item, index) {
        var self = this;

        var statusTD = $("td[name='status']", item.$el);
        statusTD.empty();
    },
    showResult: function(data) {
        var dialog = new Dialog({
            el: self.parent.$("#selftest-result-dialog"),
            title: "Self Test Result",
            readonly: ["id", "status", "output"],
            actions: ["close"]
        });

        dialog.entry = data;

        dialog.open();
    }
});

var SelfTestsPage = Page.extend({
    load: function() {
        var self = this;

        var table = new SelfTestsTable({
            el: self.$("table[name='selftests']"),
            collection: new SelfTestCollection(),
            parent: self
        });

        table.render();
    }
});
