# Dockerfile
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /app

# Copy requirements first to leverage Docker caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Set instance folder path for SQLite
ENV INSTANCE_PATH=/app/instance

# Create instance folder
RUN mkdir -p $INSTANCE_PATH

# Expose the application port
EXPOSE 5000

# Command to run the app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "wsgi:app"]
