package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigLong;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class InstanceJenkinsProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceJenkinsProvider.class);

    private static final String URI_INSTANCE_ID_PREFIX = "athenz://instanceid/";
    private static final String URI_SPIFFE_PREFIX = "spiffe://";

    static final String JENKINS_PROP_PROVIDER_DNS_SUFFIX  = "athenz.zts.jenkins.provider_dns_suffix";
    static final String JENKINS_PROP_BOOT_TIME_OFFSET     = "athenz.zts.jenkins.boot_time_offset";
    static final String JENKINS_PROP_CERT_EXPIRY_MINUTES  = "athenz.zts.jenkins.cert_expiry_minutes";
    static final String JENKINS_PROP_AUDIENCE             = "athenz.zts.jenkins.audience";
    static final String JENKINS_PROP_ISSUER               = "athenz.zts.jenkins.issuer";
    static final String JENKINS_PROP_JWKS_URI             = "athenz.zts.jenkins.jwks_uri";

    static final String JENKINS_ISSUER          = "https://jenkins.athenz.svc.cluster.local/oidc";
    static final String JENKINS_ISSUER_JWKS_URI = "https://jenkins.athenz.svc.cluster.local/oidc/jwks";

    Set<String> dnsSuffixes = null;
    String jenkinsIssuer = null;
    String provider = null;
    String audience = null;
    JwtsSigningKeyResolver signingKeyResolver = null;
    JwtsSigningKeyResolver keyStoreSigningKeyResolver = null;
    Authorizer authorizer = null;
    DynamicConfigLong bootTimeOffsetSeconds;
    long certExpiryTime;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        // save our provider name

        this.provider = provider;

        // lookup the zts audience. if not specified we'll default to athenz.io

        audience = System.getProperty(JENKINS_PROP_AUDIENCE, "athenz.io");

        // determine the dns suffix. if this is not specified we'll just default to github-actions.athenz.cloud

        final String dnsSuffix = System.getProperty(JENKINS_PROP_PROVIDER_DNS_SUFFIX, "jenkins.athenz.io");
        dnsSuffixes = new HashSet<>();
        dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));

        // how long the instance must be booted in the past before we
        // stop validating the instance requests

        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffsetSeconds = new DynamicConfigLong(CONFIG_MANAGER, JENKINS_PROP_BOOT_TIME_OFFSET, timeout);

        // get default/max expiry time for any generated tokens - 6 hours

        certExpiryTime = Long.parseLong(System.getProperty(JENKINS_PROP_CERT_EXPIRY_MINUTES, "360"));

        // initialize our jwt key resolver

        jenkinsIssuer = System.getProperty(JENKINS_PROP_ISSUER, JENKINS_ISSUER);
        signingKeyResolver = new JwtsSigningKeyResolver(extractJenkinsIssuerJwksUri(jenkinsIssuer), null);
        keyStoreSigningKeyResolver = new JwtsSigningKeyResolver(null, null);
    }

    HttpDriver getHttpDriver(String url) {
        return new HttpDriver.Builder(url, null).build();
    }

    String extractJenkinsIssuerJwksUri(final String issuer) {

        // if we have the value configured then that's what we're going to use

        String jwksUri = System.getProperty(JENKINS_PROP_JWKS_URI);
        if (!StringUtil.isEmpty(jwksUri)) {
            return jwksUri;
        }

        // otherwise we'll assume the issuer follows the standard and
        // includes the jwks uri in its openid configuration

        try (HttpDriver httpDriver = getHttpDriver(issuer)) {
            String openIdConfig = httpDriver.doGet("/.well-known/openid-configuration", null);
            if (!StringUtil.isEmpty(openIdConfig)) {
                Struct openIdConfigStruct = JSON.fromString(openIdConfig, Struct.class);
                if (openIdConfigStruct != null) {
                    jwksUri = openIdConfigStruct.getString("jwks_uri");
                }
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to retrieve openid configuration from issuer: {}", issuer, ex);
        }

        // if we still don't have a value we'll just return the default value

        return StringUtil.isEmpty(jwksUri) ? JENKINS_ISSUER_JWKS_URI : jwksUri;
    }

    private ResourceException forbiddenError(String message) {
        LOGGER.error(message);
        return new ResourceException(ResourceException.FORBIDDEN, message);
    }

    @Override
    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {

        // before running any checks make sure we have a valid authorizer

        if (authorizer == null) {
            throw forbiddenError("Authorizer not available");
        }

        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        final Map<String, String> instanceAttributes = confirmation.getAttributes();

        // our request must not have any sanIPs or hostnames

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_IP))) {
            throw forbiddenError("Request must not have any sanIP addresses");
        }

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_HOSTNAME))) {
            throw forbiddenError("Request must not have any sanDNS values");
        }

        // validate san URI

        if (!validateSanUri(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_URI))) {
            throw forbiddenError("Unable to validate certificate request sanURI values");
        }

        // we need to validate the token which is our attestation
        // data for the service requesting a certificate


        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw forbiddenError("Jenkins ID Token must be provided");
        }

        StringBuilder errMsg = new StringBuilder(256);
        final String reqInstanceId = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_ID);
        if (!validateOIDCToken(attestationData, instanceDomain, instanceService, reqInstanceId, errMsg)) {
            throw forbiddenError("Unable to validate Certificate Request with the provided ID Token: " + errMsg.toString());
        }

        // validate the certificate san DNS names

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffixes, null, null, false, instanceId, null)) {
            throw forbiddenError("Unable to validate certificate request sanDNS entries");
        }

        // set our cert attributes in the return object.
        // for GitHub Actions we do not allow refresh of those certificates, and
        // the issued certificate can only be used by clients and not servers

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_REFRESH, "false");
        attributes.put(InstanceProvider.ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certExpiryTime));

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {

        // we do not allow refresh of GitHub actions certificates

        throw forbiddenError("GitHub Action X.509 Certificates cannot be refreshed");
    }

    /**
     * verifies that sanUri only contains the spiffe and instance id uris
     * @param sanUri the SAN URI value
     * @return true if it only contains spiffe and instance id uris, otherwise false
     */
    boolean validateSanUri(final String sanUri) {

        if (StringUtil.isEmpty(sanUri)) {
            LOGGER.debug("Request contains no sanURI to verify");
            return true;
        }

        for (String uri: sanUri.split(",")) {
            if (uri.startsWith(URI_SPIFFE_PREFIX) || uri.startsWith(URI_INSTANCE_ID_PREFIX)) {
                continue;
            }
            LOGGER.error("Request contains unsupported uri value: {}", uri);
            return false;
        }

        return true;
    }

    boolean validateOIDCToken(final String jwToken, final String domainName, final String serviceName,
            final String instanceId, StringBuilder errMsg) {

        Jws<Claims> claims;
        try {
             claims = Jwts.parserBuilder()
                    .setSigningKeyResolver(signingKeyResolver)
                    .setAllowedClockSkewSeconds(60)
                    .build()
                    .parseClaimsJws(jwToken);
        } catch (Exception e) {
            errMsg.append("Unable to parse and validate token with JWKs: ").append(e.getMessage());
            try {
                 claims = Jwts.parserBuilder()
                        .setSigningKeyResolver(keyStoreSigningKeyResolver)
                        .setAllowedClockSkewSeconds(60)
                        .build()
                        .parseClaimsJws(jwToken);
            } catch (Exception ex) {
                errMsg.append("Unable to parse and validate token with Key Store: ").append(ex.getMessage());
            	return false;
            }
        }

        // verify the issuer in set to GitHub Actions

        Claims claimsBody = claims.getBody();
        if (!jenkinsIssuer.equals(claimsBody.getIssuer())) {
            errMsg.append("token issuer is not Jenkins: ").append(claimsBody.getIssuer());
            return false;
        }

        // verify that token audience is set for our service

        if (!audience.equals(claimsBody.getAudience())) {
            errMsg.append("token audience is not ZTS Server audience: ").append(claimsBody.getAudience());
            return false;
        }

        // need to verify that the issue time is within our configured bootstrap time

        Date issueDate = claimsBody.getIssuedAt();
        if (issueDate == null || issueDate.getTime() < System.currentTimeMillis() -
                TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds.get())) {
            errMsg.append("job start time is not recent enough, issued at: ").append(issueDate);
            return false;
        }

        // verify the domain and service names in the token based on our configuration

        return validateTenantDomainToken(claimsBody, domainName, serviceName, errMsg);
    }

    boolean validateTenantDomainToken(final Claims claims, final String domainName, final String serviceName,
            StringBuilder errMsg) {

        // we need to extract and generate our action value for the authz check

        final String action = "jenkins.job";

        // we need to generate our resource value based on the subject

        final String subject = claims.getSubject();
        if (StringUtil.isEmpty(subject)) {
            errMsg.append("token does not contain required subject claim");
            return false;
        }

        // generate our principal object and carry out authorization check

        final String resource = domainName + ":" + subject;
        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);
        boolean accessCheck = authorizer.access(action, resource, principal, null);
        if (!accessCheck) {
            errMsg.append("authorization check failed for action: ").append(action)
                    .append(" resource: ").append(resource);
        }
        return accessCheck;
    }
}
