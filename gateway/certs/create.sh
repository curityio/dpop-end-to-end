cd "$(dirname "${BASH_SOURCE[0]}")"

######################################################################
# A utility to create wildcard certificates for local test deployments
######################################################################

ROOT_CERT_FILE_PREFIX='example.ca'
ROOT_CERT_DESCRIPTION='DPoP Local CA'
SSL_CERT_FILE_PREFIX='example.ssl'
SSL_CERT_PASSWORD='Password1'
WILDCARD_DOMAIN_NAME='*.demo.example'

#
# Do nothing if files exist already, to prevent the user needing to reconfigure trust for the root CA
#
if [ -f $SSL_CERT_FILE_PREFIX.crt ]; then
  exit 0
fi

#
# Ensure the correct OpenSSL behavior on Windows with Git bash
#
if [[ "$(uname -s)" == MINGW64* ]]; then
  export MSYS_NO_PATHCONV=1
fi

#
# Run the Open SSL commands
#
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out $ROOT_CERT_FILE_PREFIX.key
if [ $? -ne 0 ]; then
  echo 'Problem encountered creating the Root CA key'
  exit 1
fi

openssl req \
    -x509 \
    -new \
    -key $ROOT_CERT_FILE_PREFIX.key \
    -out $ROOT_CERT_FILE_PREFIX.crt \
    -subj "/CN=$ROOT_CERT_DESCRIPTION" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -days 3650
if [ $? -ne 0 ]; then
  echo 'Problem encountered creating the Root CA'
  exit 1
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out $SSL_CERT_FILE_PREFIX.key
if [ $? -ne 0 ]; then
  echo 'Problem encountered creating the SSL key'
  exit 1
fi

openssl req \
    -new \
    -key $SSL_CERT_FILE_PREFIX.key \
    -out $SSL_CERT_FILE_PREFIX.csr \
    -subj "/CN=$WILDCARD_DOMAIN_NAME" \
    -addext 'basicConstraints=critical,CA:FALSE'
if [ $? -ne 0 ]; then
  echo 'Problem encountered creating the SSL certificate signing request'
  exit 1
fi

openssl x509 -req \
    -in $SSL_CERT_FILE_PREFIX.csr \
    -CA $ROOT_CERT_FILE_PREFIX.crt \
    -CAkey $ROOT_CERT_FILE_PREFIX.key \
    -out $SSL_CERT_FILE_PREFIX.crt \
    -days 365 \
    -extfile server.ext
if [ $? -ne 0 ]; then
  echo 'Problem encountered creating the SSL certificate'
  exit 1
fi

rm example.ssl.csr
chmod 644 $SSL_CERT_FILE_PREFIX.key