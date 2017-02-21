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
 * Copyright (C) 2017 Red Hat, Inc.
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
    },
    getInfo: function(options) {
        $.ajax({
            type: "GET",
            url: "/pki/rest/info",
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    },
    login: function(options) {
        $.ajax({
            type: "POST",
            url: "/pki/rest/login",
            dataType: "json"
        }).done(function(data, textStatus, jqXHR) {
            if (options.success) options.success.call(self, data, textStatus, jqXHR);
        }).fail(function(jqXHR, textStatus, errorThrown) {
            if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
        });
    },
    logout: function(options) {
        options = options || {};
        if (window.crypto && typeof window.crypto.logout === "function") { // Firefox
            window.crypto.logout();
            if (options.success) options.success.call();

        } else {
            var result = document.execCommand("ClearAuthenticationCache", false);
            if (result) { // IE
                if (options.success) options.success.call();

            } else { // logout not supported
                if (options.error) options.error.call();
            }
        }
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
    initialize: function(models, options) {
        var self = this;
        Collection.__super__.initialize.call(self, models, options);

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
