package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;

import static org.testng.Assert.*;

public class InstanceJenkinsProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/unit_test_ec_public.key");

    private static class InstanceJenkinsProviderTestImpl extends InstanceJenkinsProvider {

        HttpDriver httpDriver;

        public void setHttpDriver(HttpDriver httpDriver) {
            this.httpDriver = httpDriver;
        }

        @Override
        HttpDriver getHttpDriver(String url) {
            return httpDriver;
        }
    }

    @AfterMethod
    public void tearDown() {
        System.clearProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI);
        System.clearProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE);
    }

    @Test
    public void testInitializeWithConfig() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertEquals(provider.signingKeyResolver.getJwksUri(), "https://config.athenz.io");
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
        assertNotNull(provider.getHttpDriver("https://config.athenz.io"));
    }

    @Test
    public void testInitializeWithHttpDriver() throws IOException {

        // std test where the http driver will return null for the config object

    	InstanceJenkinsProviderTestImpl provider = new InstanceJenkinsProviderTestImpl();
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), InstanceJenkinsProvider.JENKINS_ISSUER_JWKS_URI);

        // test where the http driver will return a valid config object

        provider = new InstanceJenkinsProviderTestImpl();
        httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet("/.well-known/openid-configuration", null))
                .thenReturn("{\"jwks_uri\":\"https://athenz.io/jwks\"}");
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), "https://athenz.io/jwks");

        // test when http driver return invalid data

        provider = new InstanceJenkinsProviderTestImpl();
        httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet("/.well-known/openid-configuration", null))
                .thenReturn("invalid-json");
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), InstanceJenkinsProvider.JENKINS_ISSUER_JWKS_URI);

        // and finally throwing an exception

        provider = new InstanceJenkinsProviderTestImpl();
        httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doGet("/.well-known/openid-configuration", null))
                .thenThrow(new IOException("invalid-json"));
        provider.setHttpDriver(httpDriver);
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        assertNotNull(provider);
        assertEquals(provider.signingKeyResolver.getJwksUri(), InstanceJenkinsProvider.JENKINS_ISSUER_JWKS_URI);
    }

    @Test
    public void testConfirmInstance() {

        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("jenkins.job", "sports:https://jenkins.io/job/example-project", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenz:sia:0001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.github-actions/athenz:sia:001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.jenkins.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.jenkins");
        confirmation.setAttestationData(generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false, false, false, false));
        confirmation.setAttributes(instanceAttributes);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));
        InstanceConfirmation confirmResponse = provider.confirmInstance(confirmation);
        assertNotNull(confirmResponse);
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_USAGE), "client");
        assertEquals(confirmResponse.getAttributes().get(InstanceProvider.ZTS_CERT_EXPIRY_TIME), "360");
    }

    @Test
    public void testConfirmInstanceFailures() {

        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("jenkins.job", "sports:https://jenkins.io/job/example-project", principal, null))
                .thenReturn(true);
        provider.setAuthorizer(authorizer);

        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_ID, "athenz:sia:0001");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/default/sports/api,athenz://instanceid/sys.auth.jenkins/sports.api");
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "host1.athenz.io");

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.jenkins");
        confirmation.setAttestationData(generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false, false, false, false));
        confirmation.setAttributes(instanceAttributes);

        // without the public key we should get a token validation failure

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate Certificate Request with the provided ID Token: "));
            assertTrue(ex.getMessage().contains("Unable to parse and validate token with JWKs: A signing key must be specified if the specified JWT is digitally signed."));
        }

        // once we add the expected public key we should get a failure due to invalid san dns entry

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request sanDNS entries"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAuthorizer() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        provider.setAuthorizer(null);
        try {
            provider.confirmInstance(null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorizer not available"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanIP() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any sanIP addresses"));
        }
    }

    @Test
    public void testConfirmInstanceWithHostname() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "host1.athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Request must not have any sanDNS values"));
        }
    }

    @Test
    public void testConfirmInstanceWithSanURI() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        Map<String, String> instanceAttributes = new HashMap<>();
        instanceAttributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "spiffe://ns/athenz.production/instanceid,https://athenz.io");
        confirmation.setAttributes(instanceAttributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to validate certificate request sanURI values"));
        }
    }

    @Test
    public void testConfirmInstanceWithoutAttestationData() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Jenkins ID Token must be provided"));
        }
    }

    @Test
    public void testRefreshNotSupported() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("GitHub Action X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateSanUri() {
        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        assertTrue(provider.validateSanUri(null));
        assertTrue(provider.validateSanUri(""));
        assertTrue(provider.validateSanUri("spiffe://ns/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid"));
        assertTrue(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,spiffe://ns/athenz.production/instanceid"));
        assertFalse(provider.validateSanUri("athenz://instanceid/athenz.production/instanceid,spiffe://ns/athenz.production/instanceid,https://athenz.io"));
        assertFalse(provider.validateSanUri("athenz://hostname/host1,athenz://instanceid/athenz.production/instanceid"));
        assertFalse(provider.validateSanUri("athenz://hostname/host1"));
    }

    @Test
    public void testValidateOIDCTokenIssuerMismatch() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // our issuer will not match

        String idToken = generateIdToken("https://token-actions.githubusercontent.com",
                System.currentTimeMillis() / 1000, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token issuer is not Jenkins"));
    }

    @Test
    public void testValidateOIDCTokenAudienceMismatch() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://test.athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.github_actions",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // our audience will not match

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token audience is not ZTS Server audience"));
    }

    @Test
    public void testValidateOIDCTokenStartNotRecentEnough() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // our issue time is not recent enough

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000 - 400, false, false, false, false, false);
        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));

        // create another token without the issue time

        idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false, true, false, false);
        errMsg.setLength(0);
        result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("job start time is not recent enough"));
    }

    @Test
    public void testValidateOIDCTokenMissingSubject() {
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        // create an id token without the subject claim

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, true, false, false, false, false);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("token does not contain required subject claim"));
    }

    @Test
    public void testValidateOIDCTokenAuthorizationFailure() {

        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_JWKS_URI, "https://config.athenz.io");
        System.setProperty(InstanceJenkinsProvider.JENKINS_PROP_AUDIENCE, "https://athenz.io");

        InstanceJenkinsProvider provider = new InstanceJenkinsProvider();
        provider.initialize("sys.auth.jenkins",
                "class://com.yahoo.athenz.instance.provider.impl.InstanceJenkinsProvider", null, null);

        provider.signingKeyResolver.addPublicKey("0", Crypto.loadPublicKey(ecPublicKey));

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        Principal principal = SimplePrincipal.create("sports", "api", (String) null);
        Mockito.when(authorizer.access("jenkins.job", "sports:https://jenkins.io/job/example-project", principal, null))
                .thenReturn(false);
        provider.setAuthorizer(authorizer);

        // create an id token

        String idToken = generateIdToken("https://jenkins.athenz.svc.cluster.local/oidc",
                System.currentTimeMillis() / 1000, false, false, false, false, false);

        StringBuilder errMsg = new StringBuilder(256);
        boolean result = provider.validateOIDCToken(idToken, "sports", "api", "athenz:sia:0001", errMsg);
        assertFalse(result);
        assertTrue(errMsg.toString().contains("authorization check failed for action"));
    }
 
    private String generateIdToken(final String issuer, long currentTimeSecs, boolean skipSubject,
            boolean skipEventName, boolean skipIssuedAt, boolean skipRunId, boolean skipRepository) {

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        JwtBuilder jwtBuilder = Jwts.builder()
                .setExpiration(Date.from(Instant.ofEpochSecond(currentTimeSecs + 3600)))
                .setIssuer(issuer)
                .setAudience("https://athenz.io");
        if (!skipSubject) {
            jwtBuilder.setSubject("https://jenkins.io/job/example-project");
        }
        if (!skipEventName) {
             jwtBuilder.claim("event_name", "push");
        }
        if (!skipIssuedAt) {
            jwtBuilder.setIssuedAt(Date.from(Instant.ofEpochSecond(currentTimeSecs)));
        }

        return jwtBuilder.setHeaderParam("kid", "0").signWith(privateKey, SignatureAlgorithm.ES256).compact();
    }
}
