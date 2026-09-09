FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

# Install CMake and build tools for compiling C-dependencies like liboqs
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends cmake build-essential git
