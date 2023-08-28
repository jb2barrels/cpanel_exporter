#!/bin/bash

# Default values for flags
BASICAUTH_USERNAME=""
BASICAUTH_PASSWORD=""
PORT_HTTPS=""

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -basicauth_username)
            shift
            BASICAUTH_USERNAME="$1"
            shift
            ;;
        -basicauth_password)
            shift
            BASICAUTH_PASSWORD="$1"
            shift
            ;;
        -port_https)
            shift
            PORT_HTTPS="$1"
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

    # Create systemd service unit file
    service_file="/etc/systemd/system/cpanel_exporter.service"

    # Build ExecStart command
    exec_start_cmd="/bin/cpanel_exporter -interval 60 -interval_heavy 1800 -port 59117"
    
    # Add basic auth flags if provided
    if [ ! -z "$BASICAUTH_USERNAME" ] && [ ! -z "$BASICAUTH_PASSWORD" ]; then
        exec_start_cmd+=" -basicauth_username \"$BASICAUTH_USERNAME\" -basicauth_password \"$BASICAUTH_PASSWORD\""
    fi

    # Add https port
    if [ ! -z "$PORT_HTTPS" ]; then
        exec_start_cmd+=" -port_https \"$PORT_HTTPS\""
    fi

    service_content="[Unit]
Description=CPanel Exporter
After=network.target

[Service]
User=root
WorkingDirectory=/root
ExecStart=$exec_start_cmd

[Install]
WantedBy=multi-user.target"

    echo "$service_content" | tee $service_file > /dev/null
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
