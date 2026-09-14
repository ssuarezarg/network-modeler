# netconfig-mirror runtime image.
#
# Multi-stage on purpose. The build stage installs the package into a virtualenv
# from the source tree; the final image copies only that virtualenv. The result
# contains the installed tool and **not** the source checkout, which is what
# makes the distribution model easy to change later: building here on the
# customer's VM and building elsewhere to ship an image differ only in where
# `docker build` runs, not in what comes out.
#
# The image contains no secrets and no configuration. The HMAC key, the database
# settings and the SSH key used to push are all mounted at run time — see
# docker/run.sh. Anything placed in `ENV` or baked into a layer is readable by
# anyone who can run `docker inspect` or pull the image.

FROM python:3.12-slim AS builder

WORKDIR /src
COPY pyproject.toml ./
COPY src ./src

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir '.[db]'


FROM python:3.12-slim

# git and ssh are the tool's actual runtime dependencies for the sync stage: it
# shells out to git, and pushes over SSH.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# The mirror repository arrives as a bind mount owned by a host user, and git
# refuses to operate on a repository owned by someone else ("dubious
# ownership"). Set through GIT_CONFIG_* rather than a user's .gitconfig so it
# applies whatever UID the container is told to run as - including the host UID
# passed with `--user`, which is how the bind mounts stay writable.
ENV GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=safe.directory \
    GIT_CONFIG_VALUE_0=*

# A default non-root identity. `docker run --user "$(id -u):$(id -g)"` overrides
# it so that files written into the mounted repository belong to the host user
# rather than to this UID.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin mirror
USER 10001

WORKDIR /work
ENTRYPOINT ["netconfig-mirror"]
CMD ["--help"]
