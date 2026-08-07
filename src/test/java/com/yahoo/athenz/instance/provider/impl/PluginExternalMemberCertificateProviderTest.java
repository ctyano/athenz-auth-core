package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.*;

public class PluginExternalMemberCertificateProviderTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    @AfterMethod
    public void cleanup() {
        System.clearProperty(PluginExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_EXPIRY_MINUTES);
    }

    @Test
    public void testConfirmInstanceSuccess() throws Exception {
        String accessToken = generateToken("athenz", "john@example.com");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        assertEquals(result.getAttributes().get(PluginExternalMemberCertificateProvider.ZTS_CERT_REFRESH), "false");
        assertEquals(result.getAttributes().get(PluginExternalMemberCertificateProvider.ZTS_CERT_USAGE), "client");
        provider.close();
    }

    @Test
    public void testConfirmInstanceSubjectMatchesRawMemberName() throws Exception {
        String accessToken = generateToken("athenz", "john@example.com");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("john@example.com");
        confirmation.setAttestationData(accessToken);

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        provider.close();
    }

    @Test
    public void testConfirmInstanceCustomMemberDomain() throws Exception {
        String accessToken = generateToken("athenz", "john@example.com");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "keycloak");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("keycloak:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        provider.close();
    }

    @Test
    public void testConfirmInstanceCustomMemberClaim() throws Exception {
        String accessToken = generateToken("athenz", "john@example.com", "upn", "john@example.com");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "upn");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        provider.close();
    }

    @Test
    public void testConfirmInstanceSubjectMismatch() throws Exception {
        String accessToken = generateToken("athenz", "jane@example.com");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Token subject mismatch"));
        } finally {
            provider.close();
        }
    }

    @Test
    public void testConfirmInstanceInvalidAudience() throws Exception {
        String accessToken = generateToken("other-audience", "john@example.com");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Invalid token audience"));
        } finally {
            provider.close();
        }
    }

    @Test
    public void testConfirmInstanceMissingMemberNameClaim() throws Exception {
        String accessToken = generateTokenNoEmail("athenz", "john@example.com");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Token missing member name claim"));
        } finally {
            provider.close();
        }
    }

    @Test
    public void testConfirmInstanceIgnoresExpirationClaim() throws Exception {
        final long currentTimeMillis = System.currentTimeMillis();
        String accessToken = generateToken("athenz", "john@example.com",
                new Date(currentTimeMillis - TimeUnit.MINUTES.toMillis(1)),
                new Date(currentTimeMillis - TimeUnit.MINUTES.toMillis(1)));

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "tokenExpiryMinutes", 5L);
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        provider.close();
    }

    @Test
    public void testConfirmInstanceExpiresByIssueTime() throws Exception {
        final long currentTimeMillis = System.currentTimeMillis();
        String accessToken = generateToken("athenz", "john@example.com",
                new Date(currentTimeMillis - TimeUnit.MINUTES.toMillis(6)),
                new Date(currentTimeMillis + TimeUnit.HOURS.toMillis(1)));

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "tokenExpiryMinutes", 5L);
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Token issue time is outside allowed window"));
        } finally {
            provider.close();
        }
    }

    @Test
    public void testConfirmInstanceRequiresIssueTime() throws Exception {
        String accessToken = generateToken("athenz", "john@example.com",
                null, new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)));

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Token does not contain required iat claim"));
        } finally {
            provider.close();
        }
    }

    @Test
    public void testConfirmInstanceUsesConfiguredTokenExpiryMinutes() throws Exception {
        final long currentTimeMillis = System.currentTimeMillis();
        String accessToken = generateToken("athenz", "john@example.com",
                new Date(currentTimeMillis - TimeUnit.MINUTES.toMillis(6)),
                new Date(currentTimeMillis + TimeUnit.HOURS.toMillis(1)));

        System.setProperty(PluginExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_EXPIRY_MINUTES, "10");

        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        provider.initialize("external_member_cert", null, null, null);
        setField(provider, "idpAudience", "athenz");
        setField(provider, "memberNameClaim", "email");
        setField(provider, "memberDomain", "email");
        setField(provider, "jwtProcessor", buildLocalJwtProcessor());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setService("email:ext.john@example.com");
        confirmation.setAttestationData(accessToken);

        InstanceConfirmation result = provider.confirmInstance(confirmation);

        assertNotNull(result);
        provider.close();
    }

    @Test
    public void testParseTokenExpiryMinutes() {
        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();

        assertEquals(provider.parseTokenExpiryMinutes(null), 15);
        assertEquals(provider.parseTokenExpiryMinutes(" 10 "), 10);
        assertEquals(provider.parseTokenExpiryMinutes("0"), 15);
        assertEquals(provider.parseTokenExpiryMinutes("invalid"), 15);
    }

    @Test
    public void testConfirmInstanceMissingAttestation() throws ProviderResourceException {
        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        InstanceConfirmation confirmation = new InstanceConfirmation();

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(e.getMessage().contains("Missing attestation data"));
        } finally {
            provider.close();
        }
    }

    @Test
    public void testRefreshInstanceForbidden() throws ProviderResourceException {
        PluginExternalMemberCertificateProvider provider = new PluginExternalMemberCertificateProvider();
        try {
            provider.refreshInstance(new InstanceConfirmation());
            fail();
        } catch (ProviderResourceException e) {
            assertEquals(e.getCode(), ProviderResourceException.FORBIDDEN);
        } finally {
            provider.close();
        }
    }

    private String generateToken(String audience, String subject) throws JOSEException {
        return generateToken(audience, subject, new Date(),
                new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)));
    }

    private String generateToken(String audience, String subject, String claimName, String claimValue) throws JOSEException {
        return generateToken(audience, subject, claimName, claimValue, new Date(),
                new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)));
    }

    private String generateToken(String audience, String subject, Date issueTime, Date expirationTime) throws JOSEException {
        return generateToken(audience, subject, "email", subject, issueTime, expirationTime);
    }

    private String generateTokenNoEmail(String audience, String subject) throws JOSEException {
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(audience)
                .subject(subject)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private String generateToken(String audience, String subject, String claimName, String claimValue,
            Date issueTime, Date expirationTime) throws JOSEException {
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        ECDSASigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .audience(audience)
                .subject(subject)
                .claim(claimName, claimValue);
        if (issueTime != null) {
            claimsSetBuilder.issueTime(issueTime);
        }
        if (expirationTime != null) {
            claimsSetBuilder.expirationTime(expirationTime);
        }
        JWTClaimsSet claimsSet = claimsSetBuilder.build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(),
                claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private ConfigurableJWTProcessor<SecurityContext> buildLocalJwtProcessor() {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, loadLocalJwkSourceUnchecked());
        processor.setJWSKeySelector(keySelector);
        processor.setJWTClaimsSetVerifier(null);
        return processor;
    }

    private JWKSource<SecurityContext> loadLocalJwkSourceUnchecked() {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("jwt_jwks.json")) {
            return new ImmutableJWKSet<>(JWKSet.load(inputStream));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void setField(Object target, String fieldName, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }
}
