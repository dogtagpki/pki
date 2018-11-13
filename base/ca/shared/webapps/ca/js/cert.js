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
 * Copyright (C) 2018 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var CertificateModel = Model.extend({
    urlRoot: "/ca/rest/certs",
    parseResponse: function(response) {
        return {
            id: response.id,
            serialNumber: response.id,
            subjectDN: response.SubjectDN,
            issuerDN: response.IssuerDN,
            status: response.Status,
            notValidBefore: response.NotBefore,
            notValidAfter: response.NotAfter,
            encoded: response.Encoded,
        };
    }
});

var CertificateCollection = Collection.extend({
    urlRoot: "/ca/rest/certs",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new CertificateModel({
            id: entry.id,
            serialNumber: entry.id,
            subjectDN: entry.SubjectDN,
            issuerDN: entry.IssuerDN,
            issuedOn: entry.IssuedOn,
            issuedBy: entry.IssuedBy,
            type: entry.Type,
            version: entry.Version,
            keyLength: entry.KeyLength,
            keyAlgorithmOID: entry.KeyAlgorithmOID,
            status: entry.Status,
            notValidBefore: entry.NotValidBefore,
            notValidAfter: entry.NotValidAfter
        });
    }
});

var CertificatePage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        CertificatePage.__super__.initialize.call(self, options);
    }
});

var CertificatesTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        CertificatesTable.__super__.initialize.call(self, options);
    }
});

var CertificatesPage = Page.extend({
    load: function() {
        var self = this;

        var table = new CertificatesTable({
            el: $("table[name='certificates']"),
            collection: self.collection
        });

        table.render();
    }
});
