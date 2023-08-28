#!/bin/bash

# Check if cpanel_exporter binary exists
if [ -f "./cpanel_exporter" ]; then
    # Copy cpanel_exporter to /bin/
    cp -f ./cpanel_exporter /bin/
    echo "cpanel_exporter binary copied to /bin/"

    # Create systemd service unit file
    service_file="/etc/systemd/system/cpanel_exporter.service"
    echo "[Unit]
Description=CPanel Exporter
After=network.target

[Service]
User=root
WorkingDirectory=/root
ExecStart=/bin/cpanel_exporter -interval 60 -interval_heavy 1800 -port 59117

[Install]
WantedBy=multi-user.target" | tee $service_file > /dev/null
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
