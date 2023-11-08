package main 

import(
    "net/http"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "time"
    "flag"
    "path/filepath"
    "log"
    "strconv"
    "strings"
    
    //For self signed cert generation
    "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
    "os"
    "math/big"

    //mutex sync locks
    "sync"

    //Temp
    //"encoding/json"
)

var port string
var port_https string

//Delcare mutex as global variable, so can be used for locking/unlocking metric concurrent changes
var mu sync.Mutex

//Debug output
var debug bool
var debugMain bool

var (

    interval string
    interval_heavy string

    //Used for basic auth
	basic_auth_user  string
	basic_auth_pass  string

    //reg = prometheus.NewRegistry()
    //  reg.MustRegister(version.NewCollector("cpanel_exporter"))
    //  if err := r.Register(nc); err != nil {
    //      return nil, fmt.Errorf("couldn't register node collector: %s", err)//
    //  }
    //factory = promauto.With(reg)
    
    activeUsers = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "cpanel_users_active",
        Help: "Current Active Users",
    })

    suspendedUsers = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "cpanel_users_suspended",
        Help: "Current Active Users",
    })

    domainsConfigured = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "cpanel_domains_configured",
        Help: "Current Domains and Subdomains setup",
    })

    serverStartTime = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "cpanel_start_time_unix_timestamp",
        Help: "Current unix timestamp of server start time",
    })

    //requestCount.WithLabelValues().Add
    //requestCount.With(prometheus.Labels{"type": "delete", "user": "alice"}).Inc()

    cpanelMeta = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cpanel_meta",
            Help: "cPanel Metadata",
        },
        []string{"version","release"},
    )
    	
    cpanelPlans = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_plans",
            Help: "cPanel Plans Configured",
        },
        []string{"plan"},
    )
    
    cpanelUserBandwidthLimit = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_bandwidth_user_limit",
            Help: "cPanel uapi User Bandwidth Max Limit",
        },
        []string{"user"},
    )
    
    cpanelUserBandwidthUsed = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_bandwidth_user_used",
            Help: "cPanel uapi User Bandwidth Used",
        },
        []string{"user"},
    )

    cpanelUserBandwidthUsedPercent = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_bandwidth_user_used_percent",
            Help: "cPanel uapi User Bandwidth Used Percent",
        },
        []string{"user"},
    )

    cpanelBandwidth = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_bandwidth",
            Help: "cPanel Bandwidth Used",
        },
        []string{"user"},
    )
    
    cpanelQuota = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_quota_percent",
            Help: "cPanel Quota Percent Used",
        },
        []string{"user"},
    )
    
    
    cpanelQuotaUsed = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_quota_used",
            Help: "cPanel Quota Value Used",
        },
        []string{"user"},
    )
    
    cpanelMailboxes = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "cpanel_mailboxes_configured",
            Help: "cPanel Mailboxes",
        },
    )
    
    cpanelFTP = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "cpanel_ftp_accounts",
            Help: "cPanel FTP Accounts",
        },
    )

    cpanelSessionsEmail = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "cpanel_sessions_email",
            Help: "cPanel Webmail Session",
        },
    )

    cpanelSessionsWeb = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "cpanel_sessions_web",
            Help: "cPanel Admin Sessions",
        },
    )

    cpanelDiskUsagePercentage = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_disk_usage_percent",
            Help: "cPanel whmapi1 Disk Usage Percent",
        },
        []string{"disk"},
    )

    cpanelSystemLoadAverage = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_system_load_average",
            Help: "cPanel whmapi1 System Load Average",
        },
        []string{"load"},
    )

    cpanelSystemMemory = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_system_memory",
            Help: "cPanel Raw Free Command System Memory",
        },
        []string{"memory"},
    )

    cpanelEximLogIncomingMailCount = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_exim_log_incoming_mail_count",
            Help: "cPanel Raw Exim Log Incoming Mail Count",
        },
        []string{"count"},
    )

    cpanelEximLogOutgoingMailCount = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cpanel_exim_log_outgoing_mail_count",
            Help: "cPanel Raw Exim Log Outgoing Mail Count",
        },
        []string{"count"},
    )

)


func fetchMetrics(){
    dur,err := time.ParseDuration((interval+"s"))

    if(err!=nil){
        log.Fatal(err)
    }

    for _ = range time.Tick(dur) {
        runMetrics() 
    }
}

func fetchUapiMetrics() {
    dur,err := time.ParseDuration((interval_heavy+"s"))

    if(err!=nil){
        log.Fatal(err)
    }

    for _ = range time.Tick(dur) {
        //these are heavier
        runUapiMetrics()   
    }
}

func runUapiMetrics(){ 

    // Lock the mutex at the beginning of the function (protect against any potential concurrent metric updates)
    mu.Lock()
    // Ensure the mutex is unlocked when the function exits
    defer mu.Unlock()

    //Loop through all cPanel usernames
    for _,u := range getUsernames() {

        //User to search for statistics
        us := filepath.Base(u)

        //---------------------------------------------------------------------
        
        //Get bandwidth limit and usage sourced from uapi (The function below has already converted numbers to MB utilization)
        _,userBandwidthMax,userBandwidthUsed,userBandwidthUsedPercent := getUserBandwidthLimitAndUsage(us)

        //cPanel Bandwidth MB max limit for user
        cpanelUserBandwidthLimit.With(prometheus.Labels{"user": us }).Set(userBandwidthMax) 

        //cPanel Bandwidth MB used for user
        cpanelUserBandwidthUsed.With(prometheus.Labels{"user": us }).Set(userBandwidthUsed) 

        //cPanel Bandwidth MB limit percentage used
        cpanelUserBandwidthUsedPercent.With(prometheus.Labels{"user": us }).Set(userBandwidthUsedPercent) 

        //---------------------------------------------------------------------

        //Get file cached bandwidth utilization of user
        bw := getBandwidth(us)
        cpanelBandwidth.With(prometheus.Labels{"user": us }).Set(float64(bw))

        //---------------------------------------------------------------------

        //cPanel Quota Percentage and Used
        _,used,perc := getQuota(us)

        //cPanel Quota Percentage
        cpanelQuota.With(prometheus.Labels{"user": us }).Set(perc)

        //cPanel Quota Used
        fused,_ := strconv.ParseFloat(used,64)
        cpanelQuotaUsed.With(prometheus.Labels{"user": us }).Set(fused) 

        //---------------------------------------------------------------------
    }
}

func runMetrics(){

    // Lock the mutex at the beginning of the function (protect against any potential concurrent metric updates)
    mu.Lock()
    // Ensure the mutex is unlocked when the function exits
    defer mu.Unlock()

    users := getUsers("")
    suspended := getUsers("suspended")
    vers := cpanelVersion()
    serverStartTimeVar := getStartTimeUnixTimestamp()
    plans := getPlans()
    domains := getDomains()
    domains_ct := len(domains)
    wsess := getSessions("web")
    esess := getSessions("email")
    emails := getEmails()
        
    serverStartTime.Set(float64(serverStartTimeVar))
    domainsConfigured.Set(float64(domains_ct))
    cpanelFTP.Set(float64(len(getFTP())))
    activeUsers.Set(float64(users))
    cpanelMailboxes.Set(float64(len(emails)))
    suspendedUsers.Set(float64(suspended))
    cpanelMeta.With(prometheus.Labels{"version": vers, "release": getRelease() })
    cpanelSessionsEmail.Set(float64(esess))
    cpanelSessionsWeb.Set(float64(wsess))

    for p,ct := range plans {
        cpanelPlans.With(prometheus.Labels{"plan": p }).Set(float64(ct))
    }

    // Get disk usage percentage metrics
    response := getDiskUsagePercent()
    for _, partition := range response.Data.Partition {
        cpanelDiskUsagePercentage.WithLabelValues(partition.Disk).Set(float64(partition.Percentage))
    }

    // Get system load average metrics
    responseSystemLoad := getSystemLoadAverage()
    fifteen, _ := strconv.ParseFloat(responseSystemLoad.Data.Fifteen, 64)
    five, _ := strconv.ParseFloat(responseSystemLoad.Data.Five, 64)
    one, _ := strconv.ParseFloat(responseSystemLoad.Data.One, 64)
    cpanelSystemLoadAverage.WithLabelValues("fifteen").Set(fifteen)
    cpanelSystemLoadAverage.WithLabelValues("five").Set(five)
    cpanelSystemLoadAverage.WithLabelValues("one").Set(one)


    // Get system memory usage
    responseSystemMemory := getSystemMemory()
    total, _ := convertToFloat(responseSystemMemory.Total)
    used, _ := convertToFloat(responseSystemMemory.Used)
    free, _ := convertToFloat(responseSystemMemory.Free)
    shared, _ := convertToFloat(responseSystemMemory.Shared)
    buffcache, _ := convertToFloat(responseSystemMemory.BuffCache)
    available, _ := convertToFloat(responseSystemMemory.Available)
    cpanelSystemMemory.WithLabelValues("total").Set(total)
    cpanelSystemMemory.WithLabelValues("used").Set(used)
    cpanelSystemMemory.WithLabelValues("free").Set(free)
    cpanelSystemMemory.WithLabelValues("shared").Set(shared)
    cpanelSystemMemory.WithLabelValues("buffcache").Set(buffcache)
    cpanelSystemMemory.WithLabelValues("available").Set(available)


    // Get exim Incoming Mail Count
    responseIncomingCount, err := getEximLogIncomingMailCount()
    if err != nil {
        log.Println("responseIncomingCount err, possible empty exim log result: %s", err)
    }
    totalCountIncoming, _ := convertToFloat(responseIncomingCount)
    cpanelEximLogIncomingMailCount.WithLabelValues("count").Set(totalCountIncoming)

    // Get exim Outgoing Mail Count
    responseOutgoingCount, err := getEximLogOutgoingMailCount()
    if err != nil {
        log.Println("responseOutgoingCount err, possible empty exim log result: %s", err)
    }
    totalCountOutgoing, _ := convertToFloat(responseOutgoingCount)
    cpanelEximLogOutgoingMailCount.WithLabelValues("count").Set(totalCountOutgoing)

}

func generateSelfSignedCert(certPath, keyPath string) error {
	// Create directory if it doesn't exist
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}

	notAfter := time.Now().AddDate(100, 0, 0) // Set the certificate to expire 100 years from now

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Self-Signed"}},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return nil
}

func basicAuthMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if basic_auth_user != "" && basic_auth_pass != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != basic_auth_user || pass != basic_auth_pass {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		handler.ServeHTTP(w, r)
	})
}

//Get settings set via either command flags or environment variable settings
//cpanel users with terminal access can in most instances see the root process running and what flags, so we must instead use ENV for credentials
func getSettings() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    // Define default values for flags
    defaultPort := "59117"
    defaultPortHTTPS := ""
    defaultInterval := "60"
    defaultIntervalHeavy := "1800"

    // Add a flag to enable debug mode
    flag.BoolVar(&debug, "debug", false, "Enable debug mode")

    // Check if the DEBUG environment variable is set and use it to enable debug mode
    if strings.ToLower(os.Getenv("DEBUG")) == "true" {
        debug = true
    }

    // Check if environment variables are set and use them if available
    if envPort := os.Getenv("PORT"); envPort != "" {
        port = envPort
    } else {
        flag.StringVar(&port, "port", defaultPort, "Metrics Port")
    }

    if envPortHTTPS := os.Getenv("PORT_HTTPS"); envPortHTTPS != "" {
        port_https = envPortHTTPS
    } else {
        flag.StringVar(&port_https, "port_https", defaultPortHTTPS, "HTTPS Metrics Port")
    }

    if envInterval := os.Getenv("INTERVAL"); envInterval != "" {
        interval = envInterval
    } else {
        flag.StringVar(&interval, "interval", defaultInterval, "Check interval duration 60s by default")
    }

    if envIntervalHeavy := os.Getenv("INTERVAL_HEAVY"); envIntervalHeavy != "" {
        interval_heavy = envIntervalHeavy
    } else {
        flag.StringVar(&interval_heavy, "interval_heavy", defaultIntervalHeavy, "Bandwidth and other heavy checks interval, 1800s (30min) by default")
    }

    //Environment only settings (not via flags)
    if envBasicAuthUser := os.Getenv("BASIC_AUTH_USERNAME"); envBasicAuthUser != "" {
        basic_auth_user = envBasicAuthUser
    }

    if envBasicAuthPass := os.Getenv("BASIC_AUTH_PASSWORD"); envBasicAuthPass != "" {
        basic_auth_pass = envBasicAuthPass
    }

    // Parse flags
    flag.Parse()
}


func main_debug() {
    /*
	jsonResult, err := eximMailCounts()
    results, err := getMemoryInfo())
	if err != nil {
		log.Printf("Error: %v\n", err)
	} else {
		log.Printf("Debug Data: %s\n", results)
	}
    */

    /*
    results := cpWhmapi("--output=jsonpretty", "systemloadavg")
    log.Printf("Debug Data: %s\n", results)
    */

    //results := getSystemMemory()
    //log.Printf("Debug Data: %s\n", results)

    /*
	// Simulate the provided JSON response as a string
	jsonStr := cpWhmapi("--output=jsonpretty", "getdiskusage")

	// Unmarshal the JSON response into a cpWhmapiResponseDiskUsage struct
	var response cpWhmapiResponseDiskUsage
	if err := json.Unmarshal([]byte(jsonStr), &response); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		return
	}

	// Iterate over the partition data and create Prometheus metrics
	for _, partition := range response.Data.Partition {
		// Construct the metric name based on the disk name (partition)
		metricName := "cpanel_disk_used_percent"
		labels := `disk="` + partition.Disk + `"`
		value := partition.Percentage

		// Print the metric in Prometheus exposition format using log.Printf
		log.Printf("# TYPE %s gauge\n", metricName)
		log.Printf("%s{%s} %d\n", metricName, labels, value)
	}
    */
}


func main(){
    debugMain = false
    if(debugMain) {
        main_debug()
    } else {
        //Get flags and environment settings
        getSettings()

        //Initialize grabbing of first-time start metrics
        go runMetrics()
        go runUapiMetrics()

        //Schedule grabbing of newer metrics over an interval of time
        go fetchMetrics()
        go fetchUapiMetrics()

        //Webserver will stop and keep script running
        startWebserver()

        log.Println("Script has reached the end, this should not have happened...")
    }
}

func startWebserver() {
	httpAddr := ":" + port
	httpsAddr := ":" + port_https

	// With basic auth
	http.Handle("/metrics", basicAuthMiddleware(promhttp.Handler()))

	if basic_auth_user == "" || basic_auth_pass == "" {
		log.Println("WARNING: HTTP(S) server will run without basic authentication, as no username and password specified.")
	}

	if port_https != "" {
		certFound := false
		certPath := "/opt/cpanel_exporter/certs/server.crt"
		keyPath := "/opt/cpanel_exporter/certs/server.key"

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			if err := generateSelfSignedCert(certPath, keyPath); err != nil {
				log.Println("Error generating self-signed certificate:", err)
			} else {
				log.Println("HTTPS certs not found. Self-signed certificates generated.")
				certFound = true
			}
		} else {
			log.Println("HTTPS certificates found.")
			certFound = true
		}

		if certFound {
			// Start HTTPS server
			go func() {
				defer handlePanic() // Recover from panics in the HTTPS server
				log.Fatal(http.ListenAndServeTLS(httpsAddr, certPath, keyPath, nil))
			}()
			log.Println("HTTPS server started on port: " + port_https)
		} else {
			log.Println("HTTPS server not started, certs not found.")
		}
	} else {
        // Start HTTP server
        go func() {
            defer handlePanic() // Recover from panics in the HTTP server
            log.Println("HTTP server started with basic authentication.")
            log.Fatal(http.ListenAndServe(httpAddr, nil))
        }()
    }

	// Keep the program running
	select {}
}


func handlePanic() {
	if r := recover(); r != nil {
		log.Printf("Recovered from panic: %v", r)

		// Optional future additional recovery logic can be put here if needed.

		// Restart the servers
		go func() {
			log.Println("Restarting servers...")
			time.Sleep(60 * time.Second) // Sleep for a moment before restarting
			startWebserver()
		}()
	}
}