# Use a stable Debian base
FROM debian:bullseye-slim

# Set versions for our components
ENV NGINX_VERSION=1.24.0
ENV MODSEC_VERSION=v3.0.12
# --- FIX ---
# Set the version to 1.0.3 (no 'v')
# The extracted directory will be ModSecurity-nginx-1.0.3
ENV CONNECTOR_VERSION=1.0.3

# Install all build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    unzip \
    libcurl4-openssl-dev \
    libxml2-dev \
    libpcre2-dev \
    libyajl-dev \
    libmaxminddb-dev \
    liblmdb-dev \
    libfuzzy-dev \
    liblua5.3-dev \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Build and Install libmodsecurity3 ---
RUN cd /opt \
    && git clone --depth 1 -b $MODSEC_VERSION https://github.com/owasp-modsecurity/ModSecurity.git \
    && cd ModSecurity \
    && git submodule init \
    && git submodule update \
    && ./build.sh \
    && ./configure \
    && make \
    && make install

# --- Download Nginx and the Connector ---
RUN cd /opt \
    # Download and extract Nginx
    && wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar -xzf nginx-${NGINX_VERSION}.tar.gz \
    \
    # --- FIX ---
    # Manually add the 'v' to the URL to download the tag
    && wget https://github.com/owasp-modsecurity/ModSecurity-nginx/archive/refs/tags/v${CONNECTOR_VERSION}.tar.gz \
    # Manually add the 'v' to the tar command to match the downloaded filename
    && tar -xzf v${CONNECTOR_VERSION}.tar.gz

# --- Build and Install Nginx with the Dynamic Module ---
RUN cd /opt/nginx-${NGINX_VERSION} \
    && ./configure \
        --prefix=/usr/local/nginx \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_realip_module \
        --with-http_gzip_static_module \
        # --- FIX ---
        # This will now correctly point to ../ModSecurity-nginx-1.0.3
        --add-dynamic-module=../ModSecurity-nginx-${CONNECTOR_VERSION} \
    && make \
    && make install

# --- Install the OWASP Core Rule Set (CRS) ---


RUN cd /etc \
    && git clone https://github.com/coreruleset/coreruleset.git owasp-crs \
    && cd owasp-crs \
    # --- THIS IS THE FIX ---
    # We are checking out a specific, *vulnerable* version
    # This will make our WAF "un-patched"
    # --- END FIX ---
    && mv crs-setup.conf.example crs-setup.conf

# --- Copy Configuration Files ---
# We will create these files next
COPY nginx/nginx.conf /usr/local/nginx/conf/nginx.conf
COPY nginx/modsecurity.conf /usr/local/nginx/conf/modsecurity.conf

# Create log directories
RUN mkdir -p /var/log/nginx

# Expose port and start Nginx
EXPOSE 80
CMD ["/usr/local/nginx/sbin/nginx", "-g", "daemon off;"]