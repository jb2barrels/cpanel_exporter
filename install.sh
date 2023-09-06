#!/bin/bash

# Default values for flags
BASICAUTH_USERNAME=""
BASICAUTH_PASSWORD=""
PORT_HTTPS=""
PORT_HTTP="59117"
INTERVAL="60"
INTERVAL_HEAVY="1800"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -basic_auth_username)
            shift
            BASICAUTH_USERNAME="$1"
            shift
            ;;
        -basic_auth_password)
            shift
            BASICAUTH_PASSWORD="$1"
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
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if cpanel_exporter binary exists
if [ -f "./cpanel_exporter" ]; then
    # Copy cpanel_exporter to /bin/
    cp -f ./cpanel_exporter /bin/
    echo "cpanel_exporter binary copied to /bin/"

    BUILD_ENV_FILE="INTERVAL=${INTERVAL}
INTERVAL_HEAVY=${INTERVAL_HEAVY}
BASIC_AUTH_USERNAME=${BASIC_AUTH_USERNAME}
BASIC_AUTH_PASSWORD=${BASIC_AUTH_PASSWORD}
PORT_HTTP=${PORT_HTTP}
PORT_HTTPS=${PORT_HTTPS}"

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

    echo $BUILD_ENV_FILE > /root/cpanel_exporter.env
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
    echo "Error: cpanel_exporter binary not found in the current directory"
fi
