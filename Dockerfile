FROM python:3.12-alpine
WORKDIR /app
COPY main.py .
ENV PORT=8080
CMD ["python", "main.py"]
