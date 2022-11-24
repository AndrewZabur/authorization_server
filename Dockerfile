FROM maven:latest as builder
COPY src /authorization-server/src
COPY pom.xml /authorization-server
RUN mvn -f /authorization-server/pom.xml clean install

FROM openjdk:17-oracle
COPY --from=builder /authorization-server/target/authorization_server-1.0-SNAPSHOT.jar authorization-server.jar
EXPOSE 8080 8081
ENTRYPOINT ["java","-jar","/authorization-server.jar"]