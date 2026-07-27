package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.token.OAuth2Token;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class EmailTokenExchangeIdentityProviderTest {

    @AfterMethod
    public void cleanup() {
        System.clearProperty(EmailTokenExchangeIdentityProvider.ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_DOMAIN);
        System.clearProperty(EmailTokenExchangeIdentityProvider.ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_CLAIM);
    }

    @Test
    public void testGetTokenIdentityMapsEmailClaimToDefaultDomain() {
        OAuth2Token token = new TestOAuth2Token("audience", Map.of("email", " Athenz_User@ATHENZ.IO "));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenIdentity(token), "email:ext.athenz_user@athenz.io");
    }

    @Test
    public void testGetTokenIdentityMapsEmailClaimToConfiguredDomain() {
        System.setProperty(EmailTokenExchangeIdentityProvider.ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_DOMAIN,
                " Keycloak ");
        OAuth2Token token = new TestOAuth2Token("audience", Map.of("email", " Athenz_User@ATHENZ.IO "));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenIdentity(token), "keycloak:ext.athenz_user@athenz.io");
    }

    @Test
    public void testGetTokenIdentityMapsConfiguredEmailClaim() {
        System.setProperty(EmailTokenExchangeIdentityProvider.ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_CLAIM,
                " preferred_username ");
        OAuth2Token token = new TestOAuth2Token("audience", Map.of(
                "email", "ignored@athenz.io",
                "preferred_username", " Athenz_User@ATHENZ.IO "));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenIdentity(token), "email:ext.athenz_user@athenz.io");
    }

    @Test
    public void testGetTokenIdentityUsesDefaultDomainWithBlankConfiguredDomain() {
        System.setProperty(EmailTokenExchangeIdentityProvider.ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_DOMAIN, "  ");
        OAuth2Token token = new TestOAuth2Token("audience", Map.of("email", "athenz_user@athenz.io"));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenIdentity(token), "email:ext.athenz_user@athenz.io");
    }

    @Test
    public void testGetTokenIdentityUsesDefaultClaimWithBlankConfiguredClaim() {
        System.setProperty(EmailTokenExchangeIdentityProvider.ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_CLAIM, "  ");
        OAuth2Token token = new TestOAuth2Token("audience", Map.of("email", "athenz_user@athenz.io"));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenIdentity(token), "email:ext.athenz_user@athenz.io");
    }

    @Test
    public void testGetTokenIdentityReturnsNullWithoutEmailClaim() {
        OAuth2Token token = new TestOAuth2Token("audience", Collections.emptyMap());

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertNull(provider.getTokenIdentity(token));
    }

    @Test
    public void testGetTokenIdentityReturnsNullWithNullToken() {
        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertNull(provider.getTokenIdentity(null));
    }

    @Test
    public void testGetTokenIdentityReturnsNullWithBlankEmailClaim() {
        OAuth2Token token = new TestOAuth2Token("audience", Map.of("email", "  "));

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertNull(provider.getTokenIdentity(token));
    }

    @Test
    public void testGetTokenAudienceReturnsTokenAudience() {
        OAuth2Token token = new TestOAuth2Token("email.subdomain", Collections.emptyMap());

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenAudience(token), "email.subdomain");
    }

    @Test
    public void testGetTokenAudienceReturnsNullWithNullToken() {
        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertNull(provider.getTokenAudience(null));
    }

    @Test
    public void testGetTokenExchangeClaimsReturnsEmailClaim() {
        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenExchangeClaims(), Collections.singletonList("email"));
    }

    @Test
    public void testGetTokenExchangeClaimsReturnsConfiguredEmailClaim() {
        System.setProperty(EmailTokenExchangeIdentityProvider.ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_CLAIM,
                "preferred_username");

        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getTokenExchangeClaims(), Collections.singletonList("preferred_username"));
    }

    @Test
    public void testGetExternalDomainReturnsDefaultDomain() {
        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getExternalDomain(), "email");
    }

    @Test
    public void testGetEmailClaimNameReturnsDefaultClaim() {
        EmailTokenExchangeIdentityProvider provider = new EmailTokenExchangeIdentityProvider();

        assertEquals(provider.getEmailClaimName(), "email");
    }

    private static class TestOAuth2Token extends OAuth2Token {

        private final String audience;
        private final Map<String, Object> claims;

        TestOAuth2Token(final String audience, final Map<String, Object> claims) {
            this.audience = audience;
            this.claims = claims;
        }

        @Override
        public String getAudience() {
            return audience;
        }

        @Override
        public Object getClaim(final String name) {
            return claims.get(name);
        }
    }
}
