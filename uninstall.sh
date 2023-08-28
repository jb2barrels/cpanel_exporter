#!/bin/bash

# Stop and disable the service
systemctl stop cpanel_exporter.service
systemctl disable cpanel_exporter.service

# Delete the binary
if [ -f "/bin/cpanel_exporter" ]; then
    rm -f /bin/cpanel_exporter
    echo "cpanel_exporter binary removed from /bin/"
else
    echo "cpanel_exporter binary not found in /bin/"
fi

# Delete the service unit file
service_file="/etc/systemd/system/cpanel_exporter.service"
if [ -f "$service_file" ]; then
    rm -f "$service_file"
    echo "cpanel_exporter service unit file removed"
else
    echo "cpanel_exporter service unit file not found"
fi

# Reload systemd manager configuration
systemctl daemon-reload

echo "Uninstallation completed"