FROM maven:latest as builder
COPY src /authorization-server/src
COPY pom.xml /authorization-server
RUN mvn -f /authorization-server/pom.xml clean install

FROM openjdk:17
ARG CD_PROFILE
COPY --from=builder /authorization-server/target/authorization_server-1.0-SNAPSHOT.jar authorization-server.jar
ENV CD_PROFILE=${CD_PROFILE}
EXPOSE 8080 8081
RUN echo ${CD_PROFILE}
ENTRYPOINT ["java", "-Dspring.profiles.active=${CD_PROFILE}", "-jar", "/authorization-server.jar"]