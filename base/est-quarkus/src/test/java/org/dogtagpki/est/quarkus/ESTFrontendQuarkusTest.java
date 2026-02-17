package org.dogtagpki.est.quarkus;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.notNullValue;

/**
 * Basic tests for EST Frontend in Quarkus.
 *
 * These tests verify the basic structure of the migrated EST subsystem.
 * Full integration tests would require EST backend configuration and
 * client certificates.
 *
 * @author Claude Code (Quarkus PoC)
 */
@QuarkusTest
public class ESTFrontendQuarkusTest {

    @Test
    @Disabled("Requires EST backend configuration")
    public void testCacertsEndpoint() {
        given()
            .when()
            .get("/rest/cacerts")
            .then()
            .statusCode(200)
            .contentType("application/pkcs7-mime");
    }

    @Test
    @Disabled("Requires EST backend configuration and client certificate")
    public void testSimpleenrollRequiresAuthentication() {
        given()
            .contentType("application/pkcs10")
            .body("test-csr-data")
            .when()
            .post("/rest/simpleenroll")
            .then()
            .statusCode(401); // Should require authentication
    }

    @Test
    public void testApplicationHealthy() {
        // Verify Quarkus health check
        given()
            .when()
            .get("/q/health")
            .then()
            .statusCode(200);
    }

    @Test
    public void testApplicationMetrics() {
        // Verify Quarkus metrics are available
        given()
            .when()
            .get("/q/metrics")
            .then()
            .statusCode(200);
    }

    @Test
    @Disabled("Requires proper EST backend and authorizer configuration")
    public void testCacertsWithLabel() {
        String label = "test-label";

        given()
            .when()
            .get("/rest/" + label + "/cacerts")
            .then()
            .statusCode(200)
            .contentType("application/pkcs7-mime");
    }
}
