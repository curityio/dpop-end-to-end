FROM kong/kong:3.9-ubuntu

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends git

COPY phantom-token-plugin/*.lua /usr/local/share/lua/5.1/kong/plugins/phantom-token/
COPY dpop-sender-constrained-plugin/*.lua /usr/local/share/lua/5.1/kong/plugins/dpop-sender-constrained/

USER kong
