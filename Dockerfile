# Dockerfile
FROM python:3.8-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV INSTANCE_PATH=/app/instance

# Set the working directory in the container
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create instance folder
RUN mkdir -p $INSTANCE_PATH

# Expose the application port
EXPOSE 5000

# Command to run the app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "wsgi:app"]
