FROM kong/kong-gateway:3.14-ubuntu

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends git

RUN luarocks install kong-phantom-token 2.0.1

USER kong