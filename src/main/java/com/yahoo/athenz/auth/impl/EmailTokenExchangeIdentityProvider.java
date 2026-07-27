package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.OAuth2Token;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class EmailTokenExchangeIdentityProvider implements TokenExchangeIdentityProvider {

    public static final String ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_DOMAIN =
            "athenz.auth.token_exchange.email.domain";
    public static final String ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_CLAIM =
            "athenz.auth.token_exchange.email.claim";
    public static final String DEFAULT_EXTERNAL_DOMAIN = "email";
    public static final String DEFAULT_EMAIL_CLAIM = "email";

    private final String externalDomain;
    private final String emailClaimName;

    public EmailTokenExchangeIdentityProvider() {
        externalDomain = resolveExternalDomain();
        emailClaimName = resolveEmailClaimName();
    }

    @Override
    public String getTokenIdentity(final OAuth2Token token) {
        if (token == null) {
            return null;
        }
        final Object emailClaim = token.getClaim(emailClaimName);
        if (emailClaim == null) {
            return null;
        }

        final String email = emailClaim.toString().trim().toLowerCase(Locale.ROOT);
        return email.isEmpty() ? null : externalDomain + ":ext." + email;
    }

    @Override
    public String getTokenAudience(final OAuth2Token token) {
        return token == null ? null : token.getAudience();
    }

    @Override
    public List<String> getTokenExchangeClaims() {
        return Collections.singletonList(emailClaimName);
    }

    String getExternalDomain() {
        return externalDomain;
    }

    String getEmailClaimName() {
        return emailClaimName;
    }

    static String resolveExternalDomain() {
        final String configuredDomain = System.getProperty(ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_DOMAIN);
        if (configuredDomain == null || configuredDomain.trim().isEmpty()) {
            return DEFAULT_EXTERNAL_DOMAIN;
        }
        return configuredDomain.trim().toLowerCase(Locale.ROOT);
    }

    static String resolveEmailClaimName() {
        final String configuredClaim = System.getProperty(ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_CLAIM);
        if (configuredClaim == null || configuredClaim.trim().isEmpty()) {
            return DEFAULT_EMAIL_CLAIM;
        }
        return configuredClaim.trim();
    }
}
