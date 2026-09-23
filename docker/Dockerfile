# TwoKeyOk MiddleWare Orchestrator
#
# The ADSS Client SDK is licensed and cannot be fetched from a public
# repository, so the image is built from an already-packaged jar:
#
#   ./deploy/install-adss-sdk.sh && mvn -B clean package
#   docker build -f docker/Dockerfile -t twokeyok/orchestrator:1.0.0 .
#
FROM eclipse-temurin:21-jre-jammy

LABEL org.opencontainers.image.title="TwoKeyOk MiddleWare Orchestrator" \
      org.opencontainers.image.description="Remote signing middleware over ADSS RAS/SAM (PAdES + signature appearances)" \
      org.opencontainers.image.vendor="TwoKeyOk" \
      org.opencontainers.image.version="1.0.0"

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system twokeyok \
 && useradd --system --gid twokeyok --home-dir /opt/twokeyok/orchestrator --shell /usr/sbin/nologin twokeyok \
 && mkdir -p /opt/twokeyok/orchestrator /etc/twokeyok/orchestrator /var/log/twokeyok-orchestrator \
 && chown -R twokeyok:twokeyok /var/log/twokeyok-orchestrator

WORKDIR /opt/twokeyok/orchestrator

COPY --chown=root:twokeyok target/twokeyok-orchestrator.jar ./twokeyok-orchestrator.jar

ENV ORCHESTRATOR_CONFIG_DIR=/etc/twokeyok/orchestrator \
    LOG_DIR=/var/log/twokeyok-orchestrator \
    ORCHESTRATOR_PORT=8443 \
    JAVA_OPTS="-Xms256m -Xmx1024m -XX:+UseG1GC -Dfile.encoding=UTF-8"

# Mount the real configuration at runtime:
#   -v /etc/twokeyok/orchestrator:/etc/twokeyok/orchestrator:ro
VOLUME ["/var/log/twokeyok-orchestrator"]

USER twokeyok
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
  CMD ["sh", "-c", "curl -fsk https://localhost:${ORCHESTRATOR_PORT}/orchestrator/actuator/health || curl -fs http://localhost:${ORCHESTRATOR_PORT}/orchestrator/actuator/health || exit 1"]

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /opt/twokeyok/orchestrator/twokeyok-orchestrator.jar"]
