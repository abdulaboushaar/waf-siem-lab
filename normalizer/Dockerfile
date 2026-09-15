FROM python:3.12-slim

WORKDIR /app
COPY normalizer.py /app/normalizer.py

# Runs as root so it can read the nginx-owned modsec audit volume and write the
# lab volume. Acceptable for a single-purpose lab sidecar; a hardened version
# would put the normalizer and nginx in a shared group and drop privileges.
CMD ["python3", "/app/normalizer.py"]
