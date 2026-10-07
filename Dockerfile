# Verdigris - lightweight Python backend + vanilla HTML/CSS/JS frontend.
# Standard library only: there is nothing to install at build time, which makes
# the build fast, reproducible and immune to dependency drift on free hosts.

FROM python:3.12-slim AS runtime

# Deterministic, log-friendly runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080

WORKDIR /app

# Copy the application (see .dockerignore for what is excluded)
COPY app ./app

# Run as an unprivileged user
RUN groupadd --system --gid 1001 verdigris \
 && useradd --system --uid 1001 --gid verdigris --home-dir /app --shell /usr/sbin/nologin verdigris \
 && chown -R verdigris:verdigris /app
USER verdigris

# Render injects $PORT; the app binds 0.0.0.0 and honours it.
EXPOSE 8080

# Container-level health check (Render uses healthCheckPath, this is a backstop)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; \
port=os.environ.get('PORT','8080'); \
r=urllib.request.urlopen('http://127.0.0.1:%s/health' % port, timeout=4); \
sys.exit(0 if r.status==200 else 1)"

CMD ["python", "-m", "app.server"]
