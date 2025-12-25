FROM eclipse-temurin:17-jdk


WORKDIR /app

# Copy backend source
COPY backend ./backend

# Copy any library jars if you use them
COPY backend/lib ./backend/lib

# Compile the java files
RUN find backend -name "*.java" > sources.txt \
    && javac -cp "backend/lib/*" @sources.txt

# Expose the API port (change if you use another port)
EXPOSE 8080

# Run your main class
CMD ["java", "-cp", "backend:backend/lib/*", "com.yourapp.JavaBackendServer"]