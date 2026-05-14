FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq procps && rm -rf /var/lib/apt/lists/*
# Intentional misconfigurations: secrets baked into env vars, weak shadow
ENV DATABASE_PASSWORD=super_secret_db_pass_2024
ENV API_KEY=sk-prod-very-secret-key-do-not-share
ENV JWT_SECRET=jwt_signing_secret_weak
RUN echo "root:weakpassword" | chpasswd 2>/dev/null || true
LABEL scenario="sensitive-file-access" misconfiguration="secrets-in-env,weak-shadow"
CMD ["sleep", "infinity"]
