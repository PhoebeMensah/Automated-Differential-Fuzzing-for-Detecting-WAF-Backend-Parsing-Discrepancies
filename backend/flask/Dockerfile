FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
RUN mkdir -p logs
EXPOSE 5000
CMD ["python", "-u", "app.py"]
