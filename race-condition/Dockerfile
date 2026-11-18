FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m ctf && chown -R ctf /app
USER ctf
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "4", "--threads", "4", "app:app"]
