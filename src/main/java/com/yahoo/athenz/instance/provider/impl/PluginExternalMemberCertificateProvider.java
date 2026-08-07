package com.yahoo.athenz.instance.provider.impl;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class PluginExternalMemberCertificateProvider implements InstanceProvider {

    private static final Logger LOG = LoggerFactory.getLogger(PluginExternalMemberCertificateProvider.class);

    public static final String EXT_MEMBER_CERT_PROP_IDP_CONFIG_ENDPOINT = "athenz.zts.external_member_cert.idp_config_endpoint";
    public static final String EXT_MEMBER_CERT_PROP_IDP_JWKS_ENDPOINT   = "athenz.zts.external_member_cert.idp_jwks_endpoint";
    public static final String EXT_MEMBER_CERT_PROP_IDP_AUDIENCE        = "athenz.zts.external_member_cert.idp_audience";
    public static final String EXT_MEMBER_CERT_PROP_MEMBER_NAME_CLAIM   = "athenz.zts.external_member_cert.member_name_claim";
    public static final String EXT_MEMBER_CERT_PROP_MEMBER_DOMAIN       = "athenz.zts.external_member_cert.member_domain";
    public static final String EXT_MEMBER_CERT_PROP_TOKEN_EXPIRY_MINUTES = "athenz.zts.external_member_cert.token_expiry_minutes";
    public static final String EXT_MEMBER_CERT_PROP_CONNECT_TIMEOUT     = "athenz.zts.external_member_cert.connect_timeout";
    public static final String EXT_MEMBER_CERT_PROP_READ_TIMEOUT        = "athenz.zts.external_member_cert.read_timeout";

    private static final String DEFAULT_MEMBER_NAME_CLAIM = "email";
    private static final String DEFAULT_MEMBER_DOMAIN = "email";
    private static final long DEFAULT_TOKEN_EXPIRY_MINUTES = 15;
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 60;
    private static final int DEFAULT_TIMEOUT_MS = (int) TimeUnit.MILLISECONDS.convert(5, TimeUnit.SECONDS);

    private static final int HTTP_OK = 200;

    private String idpJwksEndpoint;
    private String idpAudience;
    private String memberNameClaim;
    private String memberDomain;
    private long tokenExpiryMinutes = DEFAULT_TOKEN_EXPIRY_MINUTES;
    private int connectTimeout;
    private int readTimeout;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private CloseableHttpClient httpClient;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(final String provider, final String providerEndpoint, final SSLContext sslContext, final KeyStore keyStore) {
        final String idpConfigEndpoint = System.getProperty(EXT_MEMBER_CERT_PROP_IDP_CONFIG_ENDPOINT);
        idpJwksEndpoint = System.getProperty(EXT_MEMBER_CERT_PROP_IDP_JWKS_ENDPOINT);

        idpAudience = System.getProperty(EXT_MEMBER_CERT_PROP_IDP_AUDIENCE);
        memberNameClaim = System.getProperty(EXT_MEMBER_CERT_PROP_MEMBER_NAME_CLAIM, DEFAULT_MEMBER_NAME_CLAIM);
        memberDomain = System.getProperty(EXT_MEMBER_CERT_PROP_MEMBER_DOMAIN, DEFAULT_MEMBER_DOMAIN);
        tokenExpiryMinutes = parseTokenExpiryMinutes(System.getProperty(EXT_MEMBER_CERT_PROP_TOKEN_EXPIRY_MINUTES));

        connectTimeout = Integer.getInteger(EXT_MEMBER_CERT_PROP_CONNECT_TIMEOUT, DEFAULT_TIMEOUT_MS);
        readTimeout = Integer.getInteger(EXT_MEMBER_CERT_PROP_READ_TIMEOUT, DEFAULT_TIMEOUT_MS);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(connectTimeout)
                .setSocketTimeout(readTimeout)
                .build();

        httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setSSLContext(sslContext)
                .build();

        if (!StringUtil.isEmpty(idpConfigEndpoint)) {
            loadConfigFromEndpoint(idpConfigEndpoint);
        }
    }

    private void loadConfigFromEndpoint(final String configEndpoint) {
        final HttpGet httpGet;
        try {
            httpGet = new HttpGet(configEndpoint);
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid OIDC configuration endpoint: {}", configEndpoint);
            return;
        }
        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            final int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HTTP_OK) {
                final HttpEntity entity = response.getEntity();
                if (entity == null) {
                    LOG.error("Failed to load OIDC configuration from {}: empty entity", configEndpoint);
                    return;
                }
                final String configJson = EntityUtils.toString(entity, StandardCharsets.UTF_8);
                final JsonNode config = objectMapper.readTree(configJson);
                if (StringUtil.isEmpty(idpJwksEndpoint) && config.has("jwks_uri")) {
                    final JsonNode node = config.get("jwks_uri");
                    if (node != null && !node.isNull()) {
                        idpJwksEndpoint = node.asText();
                    }
                }
            } else {
                LOG.error("Failed to load OIDC configuration from {}: status={}", configEndpoint, statusCode);
            }
        } catch (Exception e) {
            LOG.error("Failed to load OIDC configuration from {}: {}", configEndpoint, e.getMessage());
        }
    }

    @Override
    public void setAuthorizer(final Authorizer authorizer) {
        // Not used in this implementation as we rely on IdP for identity
    }

    @Override
    public InstanceConfirmation confirmInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw error("Missing attestation data", ProviderResourceException.FORBIDDEN);
        }

        validateToken(attestationData, confirmation.getService());

        // For external member certificates, we don't allow refresh and we set specific usage
        final Map<String, String> attributes = new HashMap<>();
        attributes.put(ZTS_CERT_REFRESH, "false");
        attributes.put(ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        confirmation.setAttributes(attributes);

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(final InstanceConfirmation confirmation) throws ProviderResourceException {
        throw error("External member certificates cannot be refreshed", ProviderResourceException.FORBIDDEN);
    }

    private void validateToken(String token, String memberName) throws ProviderResourceException {
        ConfigurableJWTProcessor<SecurityContext> processor = getJwtProcessor();
        if (processor == null) {
            throw error("JWT Processor not initialized", ProviderResourceException.INTERNAL_SERVER_ERROR);
        }
        processor.setJWTClaimsSetVerifier(null);

        try {
            JWTClaimsSet claimsSet = processor.process(token, null);
            validateNotBeforeTime(claimsSet);
            validateIssueTime(claimsSet);

            // Validate Audience
            if (StringUtil.isEmpty(idpAudience)) {
                throw error("IDP Audience not configured", ProviderResourceException.INTERNAL_SERVER_ERROR);
            }
            if (!Objects.equals(idpAudience, JwtsHelper.getAudience(claimsSet))) {
                throw error("Invalid token audience", ProviderResourceException.FORBIDDEN);
            }

            // Validate Member Name
            String principalName = JwtsHelper.getStringClaim(claimsSet, memberNameClaim);
            if (StringUtil.isEmpty(principalName)) {
                throw error("Token missing member name claim: " + memberNameClaim, ProviderResourceException.FORBIDDEN);
            }

            // The external member name in Athenz can be "email:ext.<name>" or just "<name>"
            // depending on the context. The provider expects the full external member name.
            String expectedPrincipal = memberDomain + ":ext." + principalName;
            if (!principalName.equalsIgnoreCase(memberName) && !expectedPrincipal.equalsIgnoreCase(memberName)) {
                throw error("Token subject mismatch: " + principalName + " vs " + memberName, ProviderResourceException.FORBIDDEN);
            }

        } catch (ProviderResourceException e) {
            throw e;
        } catch (Exception e) {
            throw error("Token validation failed: " + e.getMessage(), ProviderResourceException.FORBIDDEN);
        }
    }

    void validateNotBeforeTime(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        final Date notBeforeTime = claimsSet.getNotBeforeTime();
        if (notBeforeTime == null) {
            return;
        }
        if (notBeforeTime.getTime() > System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(DEFAULT_CLOCK_SKEW_SECONDS)) {
            throw error("Token before use time: " + notBeforeTime, ProviderResourceException.FORBIDDEN);
        }
    }

    void validateIssueTime(final JWTClaimsSet claimsSet) throws ProviderResourceException {
        final Date issueTime = claimsSet.getIssueTime();
        if (issueTime == null) {
            throw error("Token does not contain required iat claim", ProviderResourceException.FORBIDDEN);
        }
        if (issueTime.getTime() > System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(DEFAULT_CLOCK_SKEW_SECONDS)) {
            throw error("Token issue time is in the future: " + issueTime, ProviderResourceException.FORBIDDEN);
        }
        if (issueTime.getTime() <= System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(tokenExpiryMinutes)) {
            throw error("Token issue time is outside allowed window, issued at: " + issueTime,
                    ProviderResourceException.FORBIDDEN);
        }
    }

    private ConfigurableJWTProcessor<SecurityContext> getJwtProcessor() {
        if (jwtProcessor != null) {
            return jwtProcessor;
        }
        synchronized (this) {
            if (jwtProcessor != null) {
                return jwtProcessor;
            }
            if (StringUtil.isEmpty(idpJwksEndpoint)) {
                return null;
            }
            jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(idpJwksEndpoint, null));
            jwtProcessor.setJWTClaimsSetVerifier(null);
            return jwtProcessor;
        }
    }

    @Override
    public void close() {
        if (httpClient != null) {
            try {
                httpClient.close();
            } catch (IOException e) {
                LOG.error("Failed to close HTTP client: {}", e.getMessage());
            }
        }
    }

    long parseTokenExpiryMinutes(final String value) {
        if (StringUtil.isEmpty(value)) {
            return DEFAULT_TOKEN_EXPIRY_MINUTES;
        }
        try {
            final long parsedValue = Long.parseLong(value.trim());
            if (parsedValue > 0) {
                return parsedValue;
            }
        } catch (NumberFormatException ignored) {
            // log below with the original value
        }
        LOG.warn("Invalid external member certificate token expiry minutes configured: {}, using default: {}",
                value, DEFAULT_TOKEN_EXPIRY_MINUTES);
        return DEFAULT_TOKEN_EXPIRY_MINUTES;
    }

    private ProviderResourceException error(String message, int code) {
        LOG.error(message);
        return new ProviderResourceException(code, message);
    }
}
