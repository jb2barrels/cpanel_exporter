# cPanel Exporter for Prometheus


Exports cPanel metrics to prometheus


## Flags
```
cpanel_exporter -h
Usage of cpanel_exporter:
  -interval string
        Check interval duration 60s by default (default "60")
  -interval_heavy string
        Bandwidth and other heavy checks interval, 1800s (30min) by default (default "1800")
  -port string
        Metrics Port (default "59117")
```

## Collectors

```
# HELP cpanel_bandwidth cPanel Metadata
# TYPE cpanel_bandwidth gauge
cpanel_bandwidth{user="aaaa"} 5.248831472e+10
# HELP cpanel_domains_configured Current Domains and Subdomains setup
# TYPE cpanel_domains_configured gauge
cpanel_domains_configured 375
# HELP cpanel_ftp_accounts cPanel FTP Accounts
# TYPE cpanel_ftp_accounts gauge
cpanel_ftp_accounts 119
# HELP cpanel_mailboxes_configured cPanel Mailboxes
# TYPE cpanel_mailboxes_configured gauge
cpanel_mailboxes_configured 27
# HELP cpanel_meta cPanel Metadata
# TYPE cpanel_meta counter
cpanel_meta{release="release",version="86.0 (build 19)"} 0
# HELP cpanel_plans cPanel Metadata
# TYPE cpanel_plans gauge
cpanel_plans{plan="DELUXE"} 9
cpanel_plans{plan="LITE"} 5
cpanel_plans{plan="PRO"} 3
# HELP cpanel_quota cPanel Disk Quota Percent
# TYPE cpanel_quota gauge
cpanel_quota{user="aaaa"} 8
cpanel_quota{user="bbbb"} 100
# HELP cpanel_sessions_email cPanel webmail session
# TYPE cpanel_sessions_email gauge
cpanel_sessions_email 17
# HELP cpanel_sessions_web cPanel session
# TYPE cpanel_sessions_web gauge
cpanel_sessions_web 10
# HELP cpanel_start_time_unix_timestamp Current unix timestamp of server start time
# TYPE cpanel_start_time_unix_timestamp gauge
cpanel_start_time_unix_timestamp 1.692866733e+09
# HELP cpanel_users_active Current Active Users
# TYPE cpanel_users_active gauge
cpanel_users_active 17
# HELP cpanel_users_suspended Current Active Users
# TYPE cpanel_users_suspended gauge
cpanel_users_suspended 6
```


### Quick notes
Build binary:
```
go build -modfile go.mod
```

### Run binary
```
INTERVAL=60 INTERVAL_HEAVY=1800 ./cpanel_exporter
```

### Run binary (Deprecated Legacy - Flags Method)
Passing flags is deprecated, cpanel users with access to terminal can in most instances see the root process running along with what flags were passed. In favor of security, environment variables are now preferred.
Note: Legacy method does not support basic auth via flags, those require environment only.
```
./cpanel_exporter -interval 60 -interval_heavy 1800 -port 59117
```

### Run binary with basic auth enabled
```
BASIC_AUTH_USERNAME="example_username BASIC_AUTH_PASSWORD="example_password123" INTERVAL=60 INTERVAL_HEAVY=1800 PORT=59117 ./cpanel_exporter
```

### Run binary with an optional https port enabled

Self signed certificate will by default install to /opt/cpanel_exporter/certs/
You may modify this path in cpanel_exporter.go if you'd like, or replace the certs after generation.
```
BASIC_AUTH_USERNAME="example_username BASIC_AUTH_PASSWORD="example_password123" INTERVAL=60 INTERVAL_HEAVY=1800 PORT=59117 PORT_HTTPS=59118 ./cpanel_exporter
```

### Build binary
```
./build.sh
```

### Install & Uninstall services commands
Install service
```
./install.sh
```

Flags for install.sh:
```
-basic_auth_username
-basic_auth_password
-port_https
-port #Defaults to 59117, if flag not specified
-interval #Defaults to 60, if flag not specified
-interval_heavy #Defaults to 1800, if flag not specified
```

Example Install #1 - With basic auth:
```
./install.sh -basic_auth_username "example_username" -basic_auth_password "example_password123"
```

Example Install #2 - Install with basic auth and https:
```
./install.sh -basic_auth_username "example_username" -basic_auth_password "example_password123" -port_https 59118
```

Uninstall service
```
./uninstall.sh
```
See service status
```
systemctl status cpanel_exporter
```

### Visit metrics page
```
http://example.com:59117/metrics
```

### Telegraf template for InfluxDB
- vi /etc/telegraf/telegraf.d/cpanel_metrics.conf
- Add this to telegraf config:
```
# InfluxDB to write metrics to
[[outputs.influxdb]]
  urls = ["http://123.123.123.123:8086"]
  database = "example_influx_database"
  username = "example_influx_username"
  password = "example_influx_password"

# Pull metrics from cpanel exporter
[[inputs.prometheus]]
  #Example CPanel Test Server on Lan
  urls = ['http://172.23.55.55:59117/metrics']
  
  # Optional basic authentication
  #insecure_skip_verify = true
  #username = "example_username"
  #password = "example_password123"
```