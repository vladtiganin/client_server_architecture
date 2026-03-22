FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libgmp-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/server_app/

RUN cd /app/server_app/RSA && python setup.py build_ext --inplace

EXPOSE 9090

CMD ["python", "-m", "server_app.main"]


