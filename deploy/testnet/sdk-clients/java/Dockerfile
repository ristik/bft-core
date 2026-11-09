# The public Java SDK's trust-base acceptance client: the SDK fork at the pinned commit (pins.json), built with its own Gradle wrapper, and the client compiled against its jar.
# docker build --build-arg SDK_REPO=... --build-arg SDK_COMMIT=... -f java/Dockerfile java
FROM eclipse-temurin:21-jdk-jammy@sha256:4b1a74fbffbe6b4e7b6f0171a472478282fb463790a51edf10e465d578f22b69
ARG SDK_REPO
ARG SDK_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN test -n "$SDK_REPO" && test -n "$SDK_COMMIT" \
 && git init -q /sdk && cd /sdk && git remote add origin "$SDK_REPO" && git fetch -q --depth 1 origin "$SDK_COMMIT" && git checkout -q --detach FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$SDK_COMMIT" \
 && ./gradlew --no-daemon -q jar && cp "$(ls build/libs/*.jar | grep -v -e -sources -e -javadoc | head -1)" /sdk.jar
COPY build.gradle.kts settings.gradle.kts /client/
COPY src /client/src
ENV SDK_JAR=/sdk.jar
RUN /sdk/gradlew --no-daemon -q -p /client installDist
ENV SDK_COMMIT=$SDK_COMMIT
USER 10001:10001
ENTRYPOINT ["/client/build/install/client/bin/client"]
