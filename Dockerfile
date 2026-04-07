FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=dashboard/app.py \
    FLASK_ENV=production \
    PORT=5000

# Install dependencies separately to leverage Docker cache
COPY requirements.txt /app/
RUN pip install --no-cache-dir gunicorn waitress && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . /app/

# Expose the application port
EXPOSE 5000

# Define the entry point for production
# Using gunicorn as the WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "dashboard.app:app"]
