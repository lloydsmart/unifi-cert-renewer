# syntax=docker/dockerfile:1

ARG UNIFI_IMAGE
FROM ${UNIFI_IMAGE}

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates python3 python3-venv \
    && apt-get install --no-install-recommends --only-upgrade -y \
        libssl3t64 openssl openssl-provider-legacy \
    && for package in libssl3t64 openssl openssl-provider-legacy; do \
        dpkg --compare-versions \
            "$(dpkg-query -W -f='${Version}' "$package")" \
            ge 3.5.5-1ubuntu3.6 || exit 1; \
       done \
    && python3 -m venv /opt/unifi-cert-renewer/venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/unifi-cert-renewer/requirements.txt
RUN /opt/unifi-cert-renewer/venv/bin/python -m pip install \
    --no-cache-dir --require-hashes \
    -r /opt/unifi-cert-renewer/requirements.txt

COPY src/certificate.py src/csr.py src/public_key.py src/renewal_policy.py src/secure_file.py \
    src/tls_policy.py src/unifi_client.py src/unifi_executor.py \
    src/unifi_executor_client.py src/unifi_executor_files.py src/unifi_process.py \
    src/unifi_executor_service.py src/unifi_tls.py /opt/unifi-cert-renewer/src/
COPY deployment/unifi/root/ /

# LinuxServer uses s6; Ubuntu's bundled Pebble supervisor is not required.
RUN rm -f /usr/bin/pebble
