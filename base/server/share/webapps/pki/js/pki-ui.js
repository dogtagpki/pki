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

var PKI = {
    substitute: function(content, map) {

        var newContent = "";

        // substitute ${attribute} with attribute value
        var pattern = /\${([^}]*)}/;

        while (content.length) {
            // search for ${attribute} pattern
            var index = content.search(pattern);
            if (index < 0) {
                newContent += content;
                break;
            }

            var name = RegExp.$1;
            var value = map[name];

            // replace pattern occurrence with attribute value
            newContent += content.substring(0, index) + (value === undefined ? "" : value);

            // process the remaining content
            content = content.substring(index + name.length + 3);
        }

        return newContent;
    }
};

var Model = Backbone.Model.extend({
    parseResponse: function(response) {
        return response;
    },
    parse: function(response, options) {
        return this.parseResponse(response);
    },
    createRequest: function(attributes) {
        return attributes;
    },
    save: function(attributes, options) {
        var self = this;
        if (attributes == undefined) attributes = self.attributes;
        // convert attributes into JSON request
        var request = self.createRequest(attributes);
        // remove old attributes
        if (self.isNew()) self.clear();
        // send JSON request
        Model.__super__.save.call(self, request, options);
    }
});

var Collection = Backbone.Collection.extend({
    urlRoot: null,
    initialize: function(options) {
        var self = this;

        self.options = options;
        self.links = {};
        self.query({});
    },
    url: function() {
        return this.currentURL;
    },
    parse: function(response) {
        var self = this;

        // get total entries
        self.total = self.getTotal(response);

        // parse links
        var links = self.getLinks(response);
        links = links == undefined ? [] : [].concat(links);
        self.parseLinks(links);

        // convert entries into models
        var models = [];
        var entries = self.getEntries(response);
        entries = entries == undefined ? [] : [].concat(entries);

        _(entries).each(function(entry) {
            var model = self.parseEntry(entry);
            models.push(model);
        });

        return models;
    },
    getTotal: function(response) {
        return response.total;
    },
    getEntries: function(response) {
        return null;
    },
    getLinks: function(response) {
        return null;
    },
    parseEntry: function(entry) {
        return null;
    },
    parseLinks: function(links) {
        var self = this;
        self.links = {};
        _(links).each(function(link) {
            var name = link.rel;
            var href = link.href;
            self.links[name] = href;
        });
    },
    link: function(name) {
        return this.links[name];
    },
    go: function(name) {
        var self = this;
        if (self.links[name] == undefined) return;
        self.currentURL = self.links[name];
    },
    query: function(params) {
        var self = this;

        // add default options into the params
        _.defaults(params, self.options);

        // generate query string
        var query = "";
        _(params).each(function(value, name) {
            // skip null or empty string, but don't skip 0
            if (value === null || value === "") return;
            query = query == "" ? "?" : query + "&";
            query = query + name + "=" + encodeURIComponent(value);
        });

        self.currentURL = self.urlRoot + query;
    }
});

var Page = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        Page.__super__.initialize.call(self, options);

        self.url = options.url;
    },
    open: function() {
        var self = this;
        // load template
        self.$el.load(self.url, function(response, status, xhr) {
            // load content
            self.load();
        });
    },
    load: function() {
    }
});

var Dialog = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        Dialog.__super__.initialize.call(self, options);

        self.title = options.title;

        self.readonly = options.readonly;
        // by default all fields are editable
        if (self.readonly == undefined) self.readonly = [];

        self.actions = options.actions;
        if (self.actions == undefined) {
            // by default all buttons are active
            self.actions = [];
            self.$(".modal-footer button").each(function(index) {
                var button = $(this);
                var action = button.attr("name");
                self.actions.push(action);
            });
        }

        self.handlers = {};

        // add default handlers
        self.handlers["cancel"] = function() {
            self.close();
        };
        self.handlers["close"] = function() {
            self.close();
        };

        self.$el.modal({ show: false });
    },
    render: function() {
        var self = this;

        if (self.title) {
            self.$(".modal-title").text(self.title);
        }

        // setup input fields
        self.$(".modal-body input").each(function(index) {
            var input = $(this);
            var name = input.attr("name");
            if (_.contains(self.readonly, name)) {
                input.attr("readonly", "readonly");
            } else {
                input.removeAttr("readonly");
            }
        });

        // setup buttons
        self.$(".modal-footer button").each(function(index) {
            var button = $(this);
            var action = button.attr("name");

            if (_.contains(self.actions, action)) {
                // enable buttons for specified actions
                button.show();
                button.click(function(e) {
                    var handler = self.handlers[action];
                    handler.call(self);
                    e.preventDefault();
                });

            } else {
                // hide unused buttons
                button.hide();
            }
        });

        self.load();
    },
    handler: function(name, handler) {
        var self = this;
        self.handlers[name] = handler;
    },
    open: function() {
        var self = this;
        self.render();
        self.$el.modal("show");
    },
    close: function() {
        var self = this;
        self.$el.modal("hide");

        // remove event handlers
        self.$(".modal-footer button").each(function(index) {
            var button = $(this);
            button.off("click");
        });
        self.trigger("close");
    },
    load: function() {
        var self = this;

        // load input fields
        self.$(".modal-body input").each(function(index) {
            var input = $(this);
            self.loadField(input);
        });

        // load drop-down lists
        self.$(".modal-body select").each(function(index) {
            var input = $(this);
            self.loadField(input);
        });
    },
    loadField: function(input) {
        var self = this;
        var name = input.attr("name");
        var value = self.entry[name];
        if (value === undefined) value = "";
        input.val(value);
    },
    save: function() {
        var self = this;

        // save input fields
        self.$(".modal-body input").each(function(index) {
            var input = $(this);
            self.saveField(input);
        });

        // save drop-down lists
        self.$(".modal-body select").each(function(index) {
            var input = $(this);
            self.saveField(input);
        });
    },
    saveField: function(input) {
        var self = this;
        var name = input.attr("name");
        var value = input.val();
        self.entry[name] = value;
    }
});

var ErrorDialog = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        ErrorDialog.__super__.initialize.call(self, options);

        self.title = options.title;
        self.content = options.content;
    },
    render: function() {
        var self = this;

        if (self.title) {
            self.$(".modal-title").text(self.title);
        }

        if (self.content) {
            self.$("span[name=content]").html(self.content);
        }

        self.$("button[name=close]").click(function(e) {
            self.close();
            e.preventDefault();
        });
    },
    open: function() {
        var self = this;
        self.render();
        self.$el.show();
    },
    close: function() {
        var self = this;
        self.$el.hide();
    }
});

var TableItem = Backbone.View.extend({
    initialize: function(options) {
        var self = this;
        TableItem.__super__.initialize.call(self, options);
        self.table = options.table;
        self.reset();
    },
    reset: function() {
        var self = this;
        $("td", self.$el).each(function(index) {
            var td = $(this);
            var name = td.attr("name");

            if (td.hasClass("pki-select-column")) {
                // uncheck checkbox and reset the value
                var checkbox = $("input[type='checkbox']", td);
                checkbox.attr("checked", false);
                checkbox.val("");

                // hide checkbox by hiding the label
                $("label", td).hide();

            } else {
                // empty the content
                td.html("&nbsp;");
            }
        });
    },
    render: function() {
        var self = this;
        var prefix = self.table.$el.attr("name") + "_select_";

        var templateTDs = $("td", self.table.template);
        $("td", self.$el).each(function(index) {
            var td = $(this);
            var name = td.attr("name");
            var templateTD = $(templateTDs[index]);

            if (td.hasClass("pki-select-column")) {
                // generate a unique input ID based on entry ID
                var entryID = self.get("id")
                var inputID = prefix + entryID;

                // set the checkbox ID and value
                var checkbox = $("input[type='checkbox']", td);
                checkbox.attr("id", inputID);
                checkbox.attr("checked", false);
                checkbox.val(entryID);

                // point the label to the checkbox and make it visible
                var label = $("label", td);
                label.attr("for", inputID);
                label.show();

            } else {
                self.renderColumn(td, templateTD);
            }
        });
    },
    get: function(name) {
        var self = this;
        var attribute = self.table.columnMappings[name] || name;
        return self.entry[attribute];
    },
    renderColumn: function(td, templateTD) {
        var self = this;

        // copy content from template
        var content = templateTD.html();
        var newContent = "";

        // substitute ${attribute} with attribute value
        var pattern = /\${([^}]*)}/;

        while (content.length) {
            // search for ${attribute} pattern
            var index = content.search(pattern);
            if (index < 0) {
                newContent += content;
                break;
            }

            var name = RegExp.$1;
            var value = self.get(name);

            // replace pattern occurance with attribute value
            newContent += content.substring(0, index) + (value === undefined ? "" : value);

            // process the remaining content
            content = content.substring(index + name.length + 3);
        }

        td.html(newContent);
    }
});

var Table = Backbone.View.extend({
    initialize: function(options) {
        var self = this;

        Table.__super__.initialize.call(self, options);
        self.entries = options.entries || [];
        self.columnMappings = options.columnMappings || {};
        self.mode = options.mode || "view";
        self.parent = options.parent;

        self.addDialog = options.addDialog;
        self.editDialog = options.editDialog;
        self.viewDialog = options.viewDialog;
        self.tableItem = options.tableItem || TableItem;

        // number of table rows
        self.pageSize = options.pageSize || 15;

        // current page: 1, 2, 3, ...
        self.page = 1;
        self.totalPages = 1;

        self.thead = $("thead", self.$el);
        self.buttons = $(".pki-table-buttons", self.thead);

        // setup search field handler
        self.searchField = $("input[name='search']", self.thead);
        self.searchField.keypress(function(e) {
            if (e.which == 13) {
                // show the first page of search results
                self.page = 1;
                self.render();
            }
        });

        // setup add button handler
        $("button[name='add']", self.buttons).click(function(e) {
            self.add();
        });

        // setup remove button handler
        $("button[name='remove']", self.buttons).click(function(e) {
            var items = [];
            var message = "Are you sure you want to remove the following entries?\n";

            // get selected items
            $("input:checked", self.tbody).each(function(index) {
                var input = $(this);
                var id = input.val();
                if (id == "") return;
                items.push(id);
                message = message + " - " + id + "\n";
            });

            if (items.length == 0) return;
            if (!confirm(message)) return;

            self.remove(items);
        });

        // setup select all handler
        self.selectAllCheckbox = $("input[type='checkbox']", self.thead);
        self.selectAllCheckbox.click(function(e) {
            var checked = $(this).is(":checked");
            $("input[type='checkbox']", self.tbody).prop("checked", checked);
        });

        self.tbody = $("tbody", self.$el);
        self.template = $("tr", self.tbody).detach();

        // create empty rows
        self.items = [];
        for (var i = 0; i < self.pageSize; i++) {
            var tr = self.template.clone();
            var item = new self.tableItem({
                el: tr,
                table: self
            });
            self.items.push(item);
            self.tbody.append(tr);
        }

        self.tfoot = $("tfoot", self.$el);
        self.totalEntriesField = $("span[name='totalEntries']", self.tfoot);
        self.pageField = $("input[name='page']", self.tfoot);
        self.totalPagesField = $("span[name='totalPages']", self.tfoot);

        // setup page jump handler
        self.pageField.keypress(function(e) {
            if (e.which == 13) {
                // parse user entered page number
                self.page = parseInt(self.pageField.val());
                if (isNaN(self.page)) self.page = 1;

                // make sure 1 <= page <= total pages
                self.page = Math.max(self.page, 1);
                self.page = Math.min(self.page, self.totalPages);
                self.render();
            }
        });

        // setup handlers for first, prev, next, and last buttons
        $("a[name='first']", self.tfoot).click(function(e) {
            self.page = 1;
            self.render();
            e.preventDefault();
        });
        $("a[name='prev']", self.tfoot).click(function(e) {
            self.page = Math.max(self.page - 1, 1);
            self.render();
            e.preventDefault();
        });
        $("a[name='next']", self.tfoot).click(function(e) {
            self.page = Math.min(self.page + 1, self.totalPages);
            self.render();
            e.preventDefault();
        });
        $("a[name='last']", self.tfoot).click(function(e) {
            self.page = self.totalPages;
            self.render();
            e.preventDefault();
        });
    },
    render: function() {
        var self = this;

        // perform manual filter
        var filter = self.searchField.val();
        self.filteredEntries = [];

        _(self.entries).each(function(item, index) {
            if (!self.matchesFilter(item, filter)) return;
            self.filteredEntries.push(item);
        });

        self.sort();

        // update controls
        self.renderControls();

        // display entries
        _(self.items).each(function(item, index) {
            self.renderRow(item, index);
        });
    },
    sort: function() {
        var self = this;
        // by default the list is not sorted
    },
    matchesFilter: function(entry, filter) {
        var self = this;

        // check filter against all values in the entry
        var matches = false;
        _(entry).each(function(value, key) {
            if (entry.name.indexOf(filter) >= 0) matches = true;
        });

        return matches;
    },
    renderControls: function() {
        var self = this;

        if (self.mode == "view") {
            self.buttons.hide();

        } else { // self.mode == "edit"
            self.buttons.show();
        }

        // clear selection
        self.selectAllCheckbox.attr("checked", false);

        // display total entries
        self.totalEntriesField.text(self.totalEntries());

        // display current page number
        self.pageField.val(self.page);

        // calculate and display total number of pages
        self.totalPages = Math.floor(Math.max(0, self.totalEntries() - 1) / self.pageSize) + 1;
        self.totalPagesField.text(self.totalPages);
    },
    renderRow: function(item, index) {
        var self = this;
        var i = (self.page - 1) * self.pageSize + index;
        if (i < self.filteredEntries.length) {
            // show entry in existing row
            item.entry = self.filteredEntries[i];
            item.render();

        } else {
            // clear unused row
            item.reset();
        }
    },
    totalEntries: function() {
        var self = this;
        return self.filteredEntries.length;
    },
    open: function(item) {
        var self = this;

        var dialog;
        if (self.mode == "view") {
            dialog = self.viewDialog;

        } else { // self.mode == "edit"
            dialog = self.editDialog;

            dialog.handler("save", function() {

                // save changes
                dialog.save();
                _.extend(item.entry, dialog.entry);

                // redraw table
                self.render();
                dialog.close();
            });
        }

        dialog.entry = _.clone(item.entry);

        dialog.open();
    },
    add: function() {
        var self = this;

        var dialog = self.addDialog;
        dialog.entry = {};

        dialog.handler("add", function() {

            // save new entry
            dialog.save();
            self.entries.push(dialog.entry);

            // redraw table
            self.render();
            dialog.close();
        });

        dialog.open();
    },
    remove: function(items) {
        var self = this;

        // remove selected entries
        self.entries = _.reject(self.entries, function(entry) {
            return _.contains(items, entry.id);
        });

        // redraw table
        self.render();
    }
});

var ModelTable = Table.extend({
    initialize: function(options) {
        var self = this;
        options.mode = options.mode || "edit";
        ModelTable.__super__.initialize.call(self, options);
        self.collection = options.collection;
    },
    render: function() {
        var self = this;

        // if collection is undefined, don't fetch data, just draw the controls
        if (!self.collection) {
            self.renderControls();
            return;
        }

        // set query based on current page, page size, and filter
        self.collection.query({
            start: (self.page - 1) * self.pageSize,
            size: self.pageSize,
            filter: self.searchField.val()
        });

        // fetch data based on query
        self.collection.fetch({
            reset: true,
            success: function(collection, response, options) {

                // update controls
                self.renderControls();

                // display entries
                _(self.items).each(function(item, index) {
                    self.renderRow(item, index);
                });
            },
            error: function(collection, response, options) {
                new ErrorDialog({
                    el: $("#error-dialog"),
                    title: "HTTP Error " + response.responseJSON.Code,
                    content: response.responseJSON.Message
                }).open();
            }
        });
    },
    renderRow: function(item, index) {
        var self = this;
        if (index < self.collection.length) {
            // show entry in existing row
            var model = self.collection.at(index);
            item.entry = _.clone(model.attributes);
            item.render();

        } else {
            // clear unused row
            item.reset();
        }
    },
    totalEntries: function() {
        var self = this;
        return self.collection.total;
    },
    open: function(item) {
        var self = this;

        var model = self.collection.get(item.entry.id);

        var dialog = self.editDialog;
        dialog.entry = item.entry;

        dialog.handler("save", function() {

            // save attribute changes
            dialog.save();
            model.set(dialog.entry);

            // if nothing has changed, return
            var changedAttributes = model.changedAttributes();
            if (!changedAttributes) return;

            // save changed attributes with PATCH
            model.save(changedAttributes, {
                patch: true,
                wait: true,
                success: function(model, response, options) {
                    // redraw table after saving entries
                    self.render();
                    dialog.close();
                },
                error: function(model, response, options) {
                    if (response.status == 200) {
                        // redraw table after saving entries
                        self.render();
                        dialog.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + response.responseJSON.Code,
                        content: response.responseJSON.Message
                    }).open();
                }
            });
        });

        // load data from server
        model.fetch({
            success: function(model, response, options) {
                dialog.open();
            },
            error: function(model, response, options) {
                new ErrorDialog({
                    el: $("#error-dialog"),
                    title: "HTTP Error " + response.responseJSON.Code,
                    content: response.responseJSON.Message
                }).open();
            }
        });
    },
    add: function() {
        var self = this;

        var dialog = self.addDialog;

        var model = self.collection.model.call(self.collection);
        dialog.entry = _.clone(model.attributes);

        dialog.handler("add", function() {

            // save new attributes
            dialog.save();
            var entry = {};
            _.each(dialog.entry, function(value, key) {
                if (value == "") return;
                entry[key] = value;
            });

            // save new entry with POST
            model.save(entry, {
                wait: true,
                success: function(model, response, options) {
                    // redraw table after adding new entry
                    self.render();
                    dialog.close();
                },
                error: function(model, response, options) {
                    if (response.status == 201) {
                        // redraw table after adding new entry
                        self.render();
                        dialog.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + response.responseJSON.Code,
                        content: response.responseJSON.Message
                    }).open();
                }
            });
        });

        dialog.open();
    },
    remove: function(items) {
        var self = this;

        // remove selected entries
        _.each(items, function(id, index) {
            var model = self.collection.get(id);
            model.destroy({
                wait: true,
                success: function(model, response, options) {
                    self.render();
                },
                error: function(model, response, options) {
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + response.responseJSON.Code,
                        content: response.responseJSON.Message
                    }).open();
                }
            });
        });
    }
});

var EntryPage = Page.extend({
    initialize: function(options) {
        var self = this;
        EntryPage.__super__.initialize.call(self, options);
        self.model = options.model;
        self.mode = options.mode || "view";
        self.title = options.title;
        self.editable = options.editable || [];
        self.parentPage = options.parentPage;
        self.parentHash = options.parentHash;
    },
    load: function() {
        var self = this;

        self.setup();
        self.render();
    },
    setup: function() {
        var self = this;

        self.menu = self.$(".pki-menu");
        self.editLink = $("a[name='edit']", self.menu);

        self.buttons = self.$(".pki-buttons");
        self.cancelButton = $("button[name='cancel']", self.buttons);
        self.saveButton = $("button[name='save']", self.buttons);

        self.idField = self.$("input[name='id']");
        self.statusField = self.$("input[name='status']");

        self.editLink.click(function(e) {
            self.mode = "edit";
            self.render();
            e.preventDefault();
        });

        self.cancelButton.click(function(e) {
            self.cancel();
            e.preventDefault();
        });

        self.saveButton.click(function(e) {
            self.save();
            e.preventDefault();
        });

    },
    render: function() {
        var self = this;

        if (self.mode == "add") {
            self.renderContent();
            return;
        }

        self.model.fetch({
            success: function(model, response, options) {
                self.renderContent();
            }
        });
    },
    renderContent: function() {
        var self = this;

        if (self.mode == "add") {
            // Use blank entry.
            self.entry = {};

            // Replace title.
            self.$("span[name='title']").text(self.title);

        } else {
            // Use fetched entry.
            self.entry = _.clone(self.model.attributes);

            // Update title with entry attributes.
            self.$("span[name='title']").each(function() {
                var title = $(this);
                var text = title.text();
                title.text(PKI.substitute(text, self.entry));
            });

        }

        if (self.mode == "view") {
            // All fields are read-only.
            self.$(".pki-fields input").each(function(index) {
                var input = $(this);
                input.attr("readonly", "readonly");
            });

            self.buttons.hide();
            self.menu.show();

        } else {
            self.menu.hide();

            // Show editable fields.
            self.$(".pki-fields input").each(function(index) {
                var input = $(this);
                var name = input.attr("name");
                if (_.contains(self.editable, name)) {
                    input.removeAttr("readonly");
                } else {
                    input.attr("readonly", "readonly");
                }
            });

            self.buttons.show();
        }

        self.$(".pki-fields input").each(function(index) {
            var input = $(this);
            self.loadField(input);
        });
    },
    loadField: function(input) {
        var self = this;
        var name = input.attr("name");
        var value = self.entry[name];
        if (value === undefined) value = "";
        input.val(value);
    },
    close: function() {
        var self = this;

        if (self.parentHash) {
            window.location.hash = self.parentHash;

        } else if (self.parentPage) {
            self.parentPage.open();

        } else {
            self.mode = "view";
            self.render();
        }
    },
    cancel: function() {
        var self = this;
        self.close();
    },
    save: function() {
        var self = this;

        self.saveFields();

        if (self.mode == "add") {
            // save new entry with POST
            self.model.save(self.entry, {
                wait: true,
                success: function(model, response, options) {
                    self.close();
                },
                error: function(model, response, options) {
                    if (response.status == 201) {
                        self.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + response.responseJSON.Code,
                        content: response.responseJSON.Message
                    }).open();
                }
            });
        } else {
            // save changed entry with PATCH
            self.model.save(self.entry, {
                patch: true,
                wait: true,
                success: function(model, response, options) {
                    self.close();
                },
                error: function(model, response, options) {
                    if (response.status == 200) {
                        self.close();
                        return;
                    }
                    new ErrorDialog({
                        el: $("#error-dialog"),
                        title: "HTTP Error " + response.responseJSON.Code,
                        content: response.responseJSON.Message
                    }).open();
                }
            });
        }
    },
    saveFields: function() {
        var self = this;

        self.$(".pki-fields input").each(function(index) {
            var input = $(this);
            self.saveField(input);
        });
    },
    saveField: function(input) {
        var self = this;

        var name = input.attr("name");
        var value = input.val();
        if (value == "") {
            delete self.entry[name];
        } else {
            self.entry[name] = value;
        }
    }
});
