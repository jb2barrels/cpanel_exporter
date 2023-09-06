#!/bin/bash

# Default values for flags
BASICAUTH_USERNAME=""
BASICAUTH_PASSWORD=""
PORT_HTTPS=""
PORT_HTTP="59117"
INTERVAL="60"
INTERVAL_HEAVY="1800"

#Allow downloading a binary from online, during installation instead of using ./cpanel_exporter
INSTALL_GO_BINARY_LINK=""

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -basic_auth_username)
            shift
            BASIC_AUTH_USERNAME="$1"
            shift
            ;;
        -basic_auth_password)
            shift
            BASIC_AUTH_PASSWORD="$1"
            shift
            ;;
        -port_https)
            shift
            PORT_HTTPS="$1"
            shift
            ;;
        -port)
            shift
            PORT_HTTP="$1"
            shift
            ;;
        -interval)
            shift
            INTERVAL="$1"
            shift
            ;;
        -interval_heavy)
            shift
            INTERVAL_HEAVY="$1"
            shift
            ;;
        -install_go_binary_link)
            shift
            INSTALL_GO_BINARY_LINK="$1"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

rm -f /bin/cpanel_exporter

#Download cpanel_exporter if link specified
if [ -n "$INSTALL_GO_BINARY_LINK" ]; then
    curl -L -o /bin/cpanel_exporter $INSTALL_GO_BINARY_LINK

    if [ ! -f "/bin/cpanel_exporter" ]; then
        echo "Failed to download cpanel_exporter to /bin/"
        exit -1
    fi

    chmod +x /bin/cpanel_exporter
    echo "Downloaded cpanel_exporter binary to /bin/"
else
    # Copy cpanel_exporter to /bin/
    cp -f ./cpanel_exporter /bin/

    if [ ! -f "/bin/cpanel_exporter" ]; then
        echo "Failed to copy cpanel_exporter to /bin/"
        exit -1
    fi

    chmod +x /bin/cpanel_exporter
    echo "cpanel_exporter binary copied to /bin/"
fi

# Check if cpanel_exporter binary exists
if [ -f "/bin/cpanel_exporter" ]; then

    service_content="[Unit]
Description=CPanel Exporter
After=network.target

[Service]
User=root
WorkingDirectory=/root
ExecStart=/bin/cpanel_exporter
EnvironmentFile=/root/cpanel_exporter.env

[Install]
WantedBy=multi-user.target"

    cat << EOF > /root/cpanel_exporter.env
INTERVAL=${INTERVAL}
INTERVAL_HEAVY=${INTERVAL_HEAVY}
BASIC_AUTH_USERNAME=${BASIC_AUTH_USERNAME}
BASIC_AUTH_PASSWORD=${BASIC_AUTH_PASSWORD}
PORT_HTTP=${PORT_HTTP}
PORT_HTTPS=${PORT_HTTPS}
EOF
    chown root:root /root/cpanel_exporter.env
    chmod 700 /root/cpanel_exporter.env
    echo "cpanel_exporter systemd service environment file created"

    echo "$service_content" | tee /etc/systemd/system/cpanel_exporter.service > /dev/null
    echo "cpanel_exporter systemd service unit file created"

    # Reload systemd manager configuration
    systemctl daemon-reload

    # Enable and start the service
    systemctl enable cpanel_exporter.service
    systemctl restart cpanel_exporter.service
    echo "cpanel_exporter service enabled and restarted"
else
    echo "Error: cpanel_exporter binary not found in /bin/"
fi
