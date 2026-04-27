# ============================================================
# TinyCC Cybersecurity Lab — Docker Image
# Base: Ubuntu 22.04 (jammy)
# Purpose: Isolated build environment for TinyCC experiments
# ============================================================

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------
# Step 1: Install all required dependencies
#   - build-essential : gcc, g++, make, libc-dev (needed to bootstrap
#     TinyCC and compile C programs)
#   - git             : clone the TinyCC repository
#   - python3         : used by TinyCC's test suite
#   - curl, ca-certificates : for any additional downloads
# ------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  git \
  make \
  python3 \
  python3-pip \
  curl \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------
# Step 2: Create a non-root lab user for safer operation
# ------------------------------------------------------------------
RUN useradd -m -s /bin/bash labuser

# ------------------------------------------------------------------
# Step 3: Set up the trustlab directory structure owned by labuser
# ------------------------------------------------------------------
RUN mkdir -p /home/labuser/trustlab/workspace \
  && chown -R labuser:labuser /home/labuser/trustlab

# Copy lab files into the image
COPY setup.sh   /home/labuser/setup.sh
COPY login.c    /home/labuser/trustlab/workspace/login.c
RUN chown labuser:labuser \
  /home/labuser/setup.sh \
  /home/labuser/trustlab/workspace/login.c \
  && chmod +x /home/labuser/setup.sh

# Switch to lab user from here on
USER labuser
WORKDIR /home/labuser

# ------------------------------------------------------------------
# Step 4: Run setup at image build time so every container starts
#         with TinyCC already cloned, built, and login.c compiled.
#         Network access is available during 'docker build' by default.
# ------------------------------------------------------------------
RUN bash /home/labuser/setup.sh

# Default: drop into an interactive shell ready to use.
CMD ["/bin/bash"]
