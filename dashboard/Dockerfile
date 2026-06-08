FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/dashboard
COPY ../scanner/handler.py /app/scanner/handler.py
COPY ../scanner/requirements.txt /app/scanner/requirements.txt

WORKDIR /app/dashboard

EXPOSE 5000

CMD ["python", "app.py"]
