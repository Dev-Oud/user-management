# ---- BUILD STAGE ----
    FROM maven:3.8.5-openjdk-17-slim AS build
    WORKDIR /app
    COPY . .
    RUN mvn clean package -DskipTests
    
    # ---- RUNTIME STAGE ----
    FROM openjdk:17-jdk-slim
    WORKDIR /app
    COPY --from=build /app/target/*.jar app.jar
    ENTRYPOINT ["java", "-jar", "app.jar"]
    