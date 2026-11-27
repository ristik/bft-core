// The Java acceptance client: compiled against the SDK jar built from the pinned checkout (Dockerfile: /sdk), with the dependency versions of that SDK's own build.
plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(files(System.getenv("SDK_JAR") ?: "/sdk/build/libs/sdk.jar"))
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.20.0"))
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jdk8")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    implementation("org.slf4j:slf4j-api:2.0.13")
    implementation("org.slf4j:slf4j-simple:2.0.13")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.guava:guava:33.0.0-jre")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

application {
    mainClass.set("acceptance.SdkClient")
}
