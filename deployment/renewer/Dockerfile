# syntax=docker/dockerfile:1

FROM python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f

LABEL org.opencontainers.image.source="https://github.com/lloydsmart/unifi-cert-renewer" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      net.unraid.docker.icon="https://raw.githubusercontent.com/lloydsmart/unifi-cert-renewer/main/assets/icon.png"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/unifi-cert-renewer/src

RUN groupadd --gid 1000 renewer \
    && useradd --uid 1000 --gid renewer --no-create-home --shell /usr/sbin/nologin renewer \
    && install -d -o root -g root -m 0755 /opt/unifi-cert-renewer/src

COPY requirements.txt /opt/unifi-cert-renewer/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes \
    -r /opt/unifi-cert-renewer/requirements.txt

COPY src/certificate.py src/csr.py src/opnsense_client.py src/production_renewer.py \
    src/public_key.py src/secure_file.py src/tls_policy.py src/unifi_cert_renewer.py \
    src/unifi_client.py src/unifi_executor_client.py src/unifi_tls.py \
    /opt/unifi-cert-renewer/src/
# The production entrypoint uses the documented import path, while this renewer
# image exposes only the client implementation under that name.
COPY deployment/renewer/unifi_executor_service.py \
    /opt/unifi-cert-renewer/src/unifi_executor_service.py

USER 1000:1000
ENTRYPOINT ["python", "/opt/unifi-cert-renewer/src/production_renewer.py"]
CMD ["inspect"]
