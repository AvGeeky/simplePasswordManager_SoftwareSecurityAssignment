
FROM eclipse-temurin:21

WORKDIR /app

COPY target/secure.jar app.jar

EXPOSE 8080

ENV TZ=Asia/Kolkata
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENTRYPOINT ["java", "-jar", "app.jar"]