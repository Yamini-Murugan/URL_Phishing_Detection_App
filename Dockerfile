# Initilize a base image 
FROM python:3.9-slim

# Define the current working directory
WORKDIR /app

# Copy the contents in to current working directory
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENV FLASK_APP=app.py

# Define command to start the container
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]