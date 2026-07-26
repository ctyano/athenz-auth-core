FROM docker.io/library/maven:3.9.16-eclipse-temurin-17-noble AS builder

ARG VERSION=
ARG ATHENZ_VERSION=
ARG JAVA_VERSION=17
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.opencontainers.image.version=$VERSION
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.title="Athenz Auth Core"
LABEL org.opencontainers.image.authors="ctyano <ctyano@duck.com>"
LABEL org.opencontainers.image.vendor="ctyano <ctyano@duck.com>"
LABEL org.opencontainers.image.licenses="Private"
LABEL org.opencontainers.image.url="ghcr.io/ctyano/athenz-plugins"
LABEL org.opencontainers.image.documentation="https://www.athenz.io/"
LABEL org.opencontainers.image.source="https://github.com/AthenZ/athenz"

COPY . .

RUN curl -fsSL -o /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$(dpkg --print-architecture) \
      && chmod +x /usr/local/bin/yq \
      && yq --version

RUN test -n "$ATHENZ_VERSION" || (echo "ATHENZ_VERSION build arg is required" >&2; exit 1)

RUN cat template/pom.xml \
      | yq -p xml -o xml ".project.version=strenv(VERSION)" \
      | yq -p xml -o xml ".project.properties.\"athenz.version\"=strenv(ATHENZ_VERSION)" \
      | yq -p xml -o xml ".project.properties.\"java.version\"=strenv(JAVA_VERSION)" \
      | tee pom.xml

ENV MAVEN_CONFIG=/root/.m2

RUN printf "" | openssl s_client -showcerts -connect repo.maven.apache.org:443 -servername repo.maven.apache.org 2>/dev/null \
      | awk '/BEGIN CERTIFICATE/{cert=""} {cert=cert $0 ORS} /END CERTIFICATE/{last=cert} END{printf "%s", last}' > /tmp/repo-maven-ca.pem \
      && keytool -importcert -noprompt -trustcacerts -alias repo-maven-ca -file /tmp/repo-maven-ca.pem -cacerts -storepass changeit

RUN mvn -B package --file pom.xml

FROM docker.io/library/openjdk:26-rc-slim-bookworm

ARG VERSION

COPY --from=builder /target/athenz-plugins-$VERSION.jar /target/athenz-plugins-$VERSION.jar

ENV JAR_DESTINATION=/

ENTRYPOINT ["/bin/sh", "-c", "cp -p /target/athenz-plugins-*.jar ${JAR_DESTINATION}/athenz-plugins.jar"]
