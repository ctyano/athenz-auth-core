package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.OAuth2Token;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class EmailTokenExchangeIdentityProvider implements TokenExchangeIdentityProvider {

    public static final String ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_DOMAIN =
            "athenz.auth.token_exchange.email.domain";
    public static final String DEFAULT_EXTERNAL_DOMAIN = "email";

    private final String externalDomain;

    public EmailTokenExchangeIdentityProvider() {
        externalDomain = resolveExternalDomain();
    }

    @Override
    public String getTokenIdentity(final OAuth2Token token) {
        if (token == null) {
            return null;
        }
        final Object emailClaim = token.getClaim("email");
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
        return Collections.singletonList("email");
    }

    String getExternalDomain() {
        return externalDomain;
    }

    static String resolveExternalDomain() {
        final String configuredDomain = System.getProperty(ATHENZ_PROP_TOKEN_EXCHANGE_EMAIL_DOMAIN);
        if (configuredDomain == null || configuredDomain.trim().isEmpty()) {
            return DEFAULT_EXTERNAL_DOMAIN;
        }
        return configuredDomain.trim().toLowerCase(Locale.ROOT);
    }
}
