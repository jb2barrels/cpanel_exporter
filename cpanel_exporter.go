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

    //For self signed cert generation
    "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
    "os"
    "math/big"
)

var port string
var port_https string

var (
    interval string
    interval_heavy string

    //Used for basic auth
	basicAuthUser  string
	basicAuthPass  string

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
		if basicAuthUser != "" && basicAuthPass != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != basicAuthUser || pass != basicAuthPass {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		handler.ServeHTTP(w, r)
	})
}

func main(){
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    flag.StringVar(&port, "port", "59117", "Metrics Port")

    //Set default port_https blank, incase user doesnt want to run it (As a legacy prior feature)
    flag.StringVar(&port_https, "port_https", "", "HTTPS Metrics Port")
    
    flag.StringVar(&interval, "interval","60", "Check interval duration 60s by default")
    flag.StringVar(&interval_heavy, "interval_heavy","1800", "Bandwidth and other heavy checks interval, 1800s (30min) by default")
    flag.StringVar(&basicAuthUser, "basicauth_username", "", "Basic Auth Username")
	flag.StringVar(&basicAuthPass, "basicauth_password", "", "Basic Auth Password")
    flag.Parse()

    go runMetrics()
    go runUapiMetrics()

    go fetchMetrics()
    go fetchUapiMetrics()

    //Without basic auth
    //http.Handle("/metrics", promhttp.Handler())

    //With basic auth
    http.Handle("/metrics", basicAuthMiddleware(promhttp.Handler()))

    if basicAuthUser == "" || basicAuthPass == "" {
		log.Println("WARNING: HTTP server will run without basic authentication, as no username and password specified.")
	}

    if port_https != "" {
        certFound := false
        certPath := "/opt/cpanel_exporter/certs/server.crt"
        keyPath := "/opt/cpanel_exporter/certs/server.key"

        if _, err := os.Stat(certPath); os.IsNotExist(err) {
            if err := generateSelfSignedCert(certPath, keyPath); err != nil {
                log.Println("Error generating self-signed certificate:", err)
                return
            } else {
                log.Println("HTTPS certs not found. Self signed certificates generated.")
                certFound = true
            }
        } else {
            log.Println("HTTPS certificates found.")
            certFound = true
        }

        if certFound {
            // Start HTTPS server

            //Run it like this, so the script can continue on to run the HTTP server next
            go func() {
                log.Fatal(http.ListenAndServeTLS(":"+port_https, certPath, keyPath, nil))
            }()
            log.Println("HTTPS server started on port: "+port_https)
        } else {
            log.Println("HTTPS server not started, certs not found.")
        }
    }

    log.Println("HTTP server started with basic authentication.")
    http.ListenAndServe(":"+port, nil)

    log.Println("Script has ended...")
}