// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.acme;

import java.net.URI;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

@Path("cert/{id}")
public class ACMECertificateService {

    @Context
    UriInfo uriInfo;

    @GET
    @Produces("application/pem-certificate-chain")
    public Response handleGET(@PathParam("id") String certID) throws Exception {
        return getCertificate(certID);
    }

    @POST
    @Produces("application/pem-certificate-chain")
    public Response handlePOST(@PathParam("id") String certID) throws Exception {
        return getCertificate(certID);
    }

    public Response getCertificate(String certID) {

        StringBuilder sb = new StringBuilder();

        sb.append(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIDbDCCAlSgAwIBAgICf7wwDQYJKoZIhvcNAQELBQAwMzEQMA4GA1UEChMHRVhB\n" +
                "TVBMRTEfMB0GA1UEAxMWQ0EgU2lnbmluZyBDZXJ0aWZpY2F0ZTAeFw0xOTA1MTUx\n" +
                "NzIwNTFaFw0xOTA4MTUxNzIwNTFaMC8xEDAOBgNVBAoTB0VYQU1QTEUxGzAZBgNV\n" +
                "BAMTEnNlcnZlci5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n" +
                "AQoCggEBALXUPO4Q+j+t1RAXAgncAoe4CrB3+Vsqrc54m12VRauuz/xkol2/oQE0\n" +
                "rroeAKIGrdTAMBf3yPEi42WMYgpCSPvBl8jjBE7F0YoNAJ5v+CPkISkNG00us1QF\n" +
                "giYJfhhu1fJa+Ws3nIY0YhxE8jcYJDJ0hFdEDY+OJk7zbBzVMPRlTdODzd/wiQH/\n" +
                "Nq8Cf93Ey6meykN9Z4IRcyOvReBlHNGvbXrc50E8/XXjzyRsQ418JFvP2CWjHwnS\n" +
                "BWMmvZEN1pqesPhvhe7t8cHlhb6pYERKaL70g/OjTbiFSfk8sJ+vyuM4/Z2GSZWc\n" +
                "yMO4JZjUklvjtdLbuTro9sGPL74aclUCAwEAAaOBjTCBijBCBggrBgEFBQcBAQQ2\n" +
                "MDQwMgYIKwYBBQUHMAGGJmh0dHA6Ly9zZXJ2ZXIuZXhhbXBsZS5jb206ODA4MC9j\n" +
                "YS9vY3NwMB8GA1UdIwQYMBaAFJHLDJqpFNfqQBo1Rldmn7/can+1MBMGA1UdJQQM\n" +
                "MAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
                "lZ6Gt8eFdJ8RO2n2Aw31zdslexmznf8wMPwwwZeasI1UZgrDlMt0y1MsBRZPfmGJ\n" +
                "8eZnqX1gdxDOEziqZw6hON5QqqrDQ3jyH9yqGngM5LTIpgtv/Gd3Hlefsx4O6XA5\n" +
                "FEL3obC6LvFEhVRRWKWjv3E3XqbA3OqDVraRWgWIY2o0QEEkbXmhLgZaBT1eDhUD\n" +
                "Yh8RH7WMitgEx9JlmlKP1sDUxdvgUEeBGMiRirzR0xfjsN4LP8fcddXu/wJgPa3G\n" +
                "dH0OK8kKZF1vu5tVgqY2l00IBh8KZXzEfGFZINQnw/Nd8f8Au0ibN2GvFlEDCQh+\n" +
                "LvUSERJv7Rkui3x/9qF7UQ==\n" +
                "-----END CERTIFICATE-----\n");

        sb.append(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIDizCCAnOgAwIBAgICAJEwDQYJKoZIhvcNAQELBQAwMzEQMA4GA1UEChMHRVhB\n" +
                "TVBMRTEfMB0GA1UEAxMWQ0EgU2lnbmluZyBDZXJ0aWZpY2F0ZTAeFw0xOTA1MTUx\n" +
                "NzE4MDdaFw0xOTA4MTUxNzE4MDdaMDMxEDAOBgNVBAoTB0VYQU1QTEUxHzAdBgNV\n" +
                "BAMTFkNBIFNpZ25pbmcgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQC53iuB0f90kXPkHv2/V3B+MPG70lXBZioJCaI+03xHbjwAOHnn\n" +
                "XTVGoNN3xpRdMkrNpRyy81WnsjmEJm0MSQhUGs+qyS3GYiCJtQCplw2VLQ7DhmeH\n" +
                "bemTpSoNq+OmXjJ+KPLkp5ildPmqPGHbmrDA9Sr3BHmUZxXMQIguuY8scTACJmCz\n" +
                "u8IDQok0wtvY4oo2/ZzYYRcA2HBS4++6TzpWFCjxoWFGJvbtifh0U/WC8kZl2pMj\n" +
                "O+78TjmTB+K89LeuDCRJl5FP4d+/68RFAjMVzOlz1cCVarR+w9Eka7ecP6FaHGnQ\n" +
                "Jwdf2Dk2ukhDUJt3GGQURwMJFROJTZAukG3pAgMBAAGjgagwgaUwQgYIKwYBBQUH\n" +
                "AQEENjA0MDIGCCsGAQUFBzABhiZodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tOjgw\n" +
                "ODAvY2Evb2NzcDAdBgNVHQ4EFgQUkcsMmqkU1+pAGjVGV2afv9xqf7UwHwYDVR0j\n" +
                "BBgwFoAUkcsMmqkU1+pAGjVGV2afv9xqf7UwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n" +
                "HQ8BAf8EBAMCAcYwDQYJKoZIhvcNAQELBQADggEBADYANGtbFTz+RoSZdpQh+elV\n" +
                "hEPdR+g/MEUne4KN9p6LjMtXIvXblW0lXGI/3zqfCyNVctfM+bQfDki0yfnjE0+k\n" +
                "9ndeeAR2IhVtQoaod3NbnaYJXDHbfW1WP4N5K3IVHvmC1XuotLtOSN2FL4/RdVgc\n" +
                "PadZWbimJXB+sAUUoLlLETbxpvYvH28RbwkViZm62qTVO9JA4mGZt/ScQrDRDhid\n" +
                "mJNNW+SzWXsDW+HSlB3prfVJ7akF8ShXSfzgED1oq/UMSIZZqTqDgGocKS/yl2Fx\n" +
                "tC/onhIpPUczrbUm5xfD6VJal0fm4M8FkVvuBNMi1EsCz+qcx2xR9nLKeF1cN3w=\n" +
                "-----END CERTIFICATE-----\n");

        ResponseBuilder builder = Response.ok();

        builder.header("Replay-Nonce", "MYAuvOpaoIiywTezizk5vw");

        URI link = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(link, "index");

        builder.entity(sb.toString());

        return builder.build();
    }
}
