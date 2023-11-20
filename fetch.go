package main

import (
	"bufio"
	"log"
	"os"
    "path/filepath"
    "os/exec"
	"regexp"   
	"strings"
    "io/ioutil"
    "encoding/json"
    "strconv"
    "math"
    "github.com/remeh/sizedwaitgroup"
    "fmt"
    "time"
    "net"
)

func getStartTimeUnixTimestamp() int64{
    uptimeOutput, errUptime := exec.Command("uptime", "-s").CombinedOutput()

    if errUptime != nil {
        log.Println("errUptime:")
        log.Println(errUptime)
        return -1
    }

    uptimeString := strings.TrimSpace(string(uptimeOutput))
    uptimeTime, errTimeParse := time.Parse("2006-01-02 15:04:05", uptimeString)
    if errTimeParse != nil {
        log.Println("errTimeParse:")
        log.Println(errTimeParse)
        return -1
    }

    return uptimeTime.Unix()
}

func cpanelVersion() string{
    out, err := exec.Command("/usr/local/cpanel/cpanel","-V").CombinedOutput()

    if err != nil {
        if debug {
            log.Println(err)
        }
        return ""
    }

    return string(out)
}

func getUsernames() []string {
    files := getFilesInDir("/var/cpanel/users")
    return files
}

func getUsers(typ string) int{
    files := getFilesInDir("/var/cpanel/users")

    if(typ!="suspended"){ 
        return len(files)
    }

    matches := matchFilesLine(files,"SUSPENDED=1",true)
    return len(matches)
}

type UapiResponse struct {
    ApiVersion int `json:"apiversion"`
    Module string `json:"module"`
    Func string `json:"func"`
    Result struct {
        Messages string `json:"messages"`
        Status int `json:"status"`
        Warning string `json:"warning"`
        Errors string `json:"errors"`
        Data struct {
            Http int  `json:"http"`
            MegabytesLimit interface{} `json:"megabyte_limit"`
            MegabytesRemain interface{} `json:"megabytes_remain"`
            MegabytesUsed interface{} `json:"megabytes_used"`
        } `json:"data"`   
    } `json:"result"`
}

/*
#Example Data:
#"max" data can either be "unlimited" or an actual limit such as "1 GB"
#"_max" refers to bandwidth max limit, based on the "units" value of measurement
#"_count" refers to the bandwidth used, based on the "units" value of measurement
#"percent" is total percentage of the bandwidth utilization limit used

[root@example]# uapi --output=jsonpretty --user=example StatsBar get_stats display='bandwidthusage'
{
   "module" : "StatsBar",
   "apiversion" : 3,
   "result" : {
      "status" : 1,
      "messages" : null,
      "metadata" : {
         "transformed" : 1
      },
      "data" : [
         {
            "percent5" : 0,
            "phrase" : "Monthly Bandwidth Transfer",
            "normalized" : 1,
            "_max" : "unlimited",
            "name" : "bandwidthusage",
            "near_limit_phrase" : "You have transferred [format_bytes,_1] of your [format_bytes,_2] data allotment for this month.",
            "max" : "unlimited",
            "is_maxed" : 0,
            "module" : "Stats",
            "item" : "Monthly Bandwidth Transfer",
            "role" : "WebServer",
            "maxed_phrase" : "You have transferred your maximum allotment of data ([format_bytes,_1]) for this month.",
            "count" : "20.2 MB",
            "units" : "MB",
            "percent10" : 0,
            "percent20" : 0,
            "feature" : "bandwidth",
            "id" : "bandwidthusage",
            "percent" : 0,
            "_maxed" : 0,
            "_count" : "20.20",
            "zeroisunlimited" : 1
         }
      ],
      "errors" : null,
      "warnings" : null
   },
   "func" : "get_stats"
}
*/
type UapiResponseBandwidthUsage struct {
    Module string `json:"module"`
    ApiVersion int `json:"apiversion"`
    Result struct {
        Status int `json:"status"`
        Messages string `json:"messages"`
        Metadata struct {
            Transformed int `json:"transformed"`
        } `json:"metadata"`
        Data []map[string]interface{} `json:"data"`
        Errors string `json:"errors"`
        Warning string `json:"warning"`
    } `json:"result"`
    Func string `json:"func"`
}


/*
Example:
{
   "data" : {
      "fifteen" : "0.00",
      "five" : "0.00",
      "one" : "0.00"
   },
   "metadata" : {
      "command" : "systemloadavg",
      "reason" : "OK",
      "result" : 1,
      "version" : 1
   }
}
*/
type cpWhmapiResponseLoadAverage struct {
    Data struct {
        Fifteen string `json:"fifteen"`
        Five string `json:"five"`
        One string `json:"one"`
    } `json:"data"`
    Metadata struct {
        Command string `json:"command"`
        Reason string `json:"reason"`
        Result int `json:"result"`
        Version int `json:"version"`
    } `json:"metadata"`
}

/*
Example:

{
   "data" : {
      "partition" : [
         {
            "available" : 962672,
            "device" : "/dev/loop0",
            "disk" : "loop0",
            "filesystem" : "/tmp",
            "inodes_available" : 66788,
            "inodes_ipercentage" : 0,
            "inodes_total" : 66816,
            "inodes_used" : 28,
            "mount" : "/tmp",
            "percentage" : 0,
            "total" : 1016124,
            "used" : 104
         },
         {
            "available" : 13688460,
            "device" : "/dev/sda5",
            "disk" : "sda5",
            "filesystem" : "/",
            "inodes_available" : 12830741,
            "inodes_ipercentage" : 2,
            "inodes_total" : 13065152,
            "inodes_used" : 234411,
            "mount" : "/",
            "percentage" : 48,
            "total" : 26120172,
            "used" : 12431712
         },
         {
            "available" : 460184,
            "device" : "/dev/sda2",
            "disk" : "sda2",
            "filesystem" : "/boot",
            "inodes_available" : 511674,
            "inodes_ipercentage" : 0,
            "inodes_total" : 512000,
            "inodes_used" : 326,
            "mount" : "/boot",
            "percentage" : 55,
            "total" : 1017736,
            "used" : 557552
         },
         {
            "available" : 95290,
            "device" : "/dev/sda1",
            "disk" : "sda1",
            "filesystem" : "/boot/efi",
            "inodes_available" : null,
            "inodes_ipercentage" : null,
            "inodes_total" : null,
            "inodes_used" : null,
            "mount" : "/boot/efi",
            "percentage" : 6,
            "total" : 101158,
            "used" : 5868
         },
         {
            "available" : 962672,
            "device" : "/dev/loop0",
            "disk" : "loop0",
            "filesystem" : "/var/tmp",
            "inodes_available" : 66788,
            "inodes_ipercentage" : 0,
            "inodes_total" : 66816,
            "inodes_used" : 28,
            "mount" : "/var/tmp",
            "percentage" : 0,
            "total" : 1016124,
            "used" : 104
         }
      ]
   },
   "metadata" : {
      "command" : "getdiskusage",
      "reason" : "Successfully retrieved disk usage",
      "result" : 1,
      "version" : 1
   }
}

*/
type cpWhmapiResponseDiskUsage struct {
    Data struct {
        Partition []struct {
            Available         int    `json:"available"`
            Device            string `json:"device"`
            Disk              string `json:"disk"`
            Filesystem        string `json:"filesystem"`
            InodesAvailable   int    `json:"inodes_available"`
            InodesIPercentage int    `json:"inodes_ipercentage"`
            InodesTotal       int    `json:"inodes_total"`
            InodesUsed        int    `json:"inodes_used"`
            Mount             string `json:"mount"`
            Percentage        int    `json:"percentage"`
            Total             int    `json:"total"`
            Used              int    `json:"used"`
        } `json:"partition"`
    } `json:"data"`
    Metadata struct {
        Command string `json:"command"`
        Reason  string `json:"reason"`
        Result  int    `json:"result"`
        Version int    `json:"version"`
    } `json:"metadata"`
}

// Memory struct
/*
Example:
{
  "total": 257257,
  "used": 29731,
  "free": 189925,
  "shared": 1297,
  "buff/cache": 37601,
  "available": 224457
}
*/
type cpSystemMemory struct {
    Total     int `json:"total"`
    Used      int `json:"used"`
    Free      int `json:"free"`
    Shared    int `json:"shared"`
    BuffCache int `json:"buff/cache"`
    Available int `json:"available"`
}

/*
Example:
{
   "data" : {
      "hostname" : "host1.ex.example.com"
   },
   "metadata" : {
      "command" : "gethostname",
      "reason" : "OK",
      "result" : 1,
      "version" : 1
   }
}
*/
type cpWhmapiResponseHostname struct {
    Data struct {
        Hostname string `json:"Hostname"`
    } `json:"data"`
    Metadata struct {
        Command string `json:"command"`
        Reason  string `json:"reason"`
        Result  int    `json:"result"`
        Version int    `json:"version"`
    } `json:"metadata"`
}


/*
Example:

{
   "data" : {
      "records" : [
         {
            "DEFERCOUNT" : 386,
            "DEFERFAILCOUNT" : 469,
            "DOMAIN" : "",
            "FAILCOUNT" : 83,
            "OWNER" : "root",
            "PRIMARY_DOMAIN" : "",
            "REACHED_MAXDEFERFAIL" : 0,
            "REACHED_MAXEMAILS" : 0,
            "SENDCOUNT" : 634,
            "SUCCESSCOUNT" : 551,
            "TOTALSIZE" : 33506067,
            "USER" : "-remote-"
         },
         {
            "DEFERCOUNT" : 0,
            "DEFERFAILCOUNT" : 0,
            "DOMAIN" : "example1.com",
            "FAILCOUNT" : 0,
            "OWNER" : "examplereseller",
            "PRIMARY_DOMAIN" : "example1.com",
            "REACHED_MAXDEFERFAIL" : 0,
            "REACHED_MAXEMAILS" : 0,
            "SENDCOUNT" : 31,
            "SUCCESSCOUNT" : 34,
            "TOTALSIZE" : 85689191,
            "USER" : "lotsofexampleusers12345"
         },
         {
            "DEFERCOUNT" : 0,
            "DEFERFAILCOUNT" : 0,
            "DOMAIN" : "-system-",
            "FAILCOUNT" : 0,
            "OWNER" : "root",
            "PRIMARY_DOMAIN" : "",
            "REACHED_MAXDEFERFAIL" : 0,
            "REACHED_MAXEMAILS" : 0,
            "SENDCOUNT" : 24,
            "SUCCESSCOUNT" : 24,
            "TOTALSIZE" : 75129,
            "USER" : "root"
         },
         {
            "DEFERCOUNT" : 0,
            "DEFERFAILCOUNT" : 0,
            "DOMAIN" : "l-and-example.com",
            "FAILCOUNT" : 0,
            "OWNER" : "examplereseller",
            "PRIMARY_DOMAIN" : "l-and-example.com",
            "REACHED_MAXDEFERFAIL" : 0,
            "REACHED_MAXEMAILS" : 0,
            "SENDCOUNT" : 19,
            "SUCCESSCOUNT" : 35,
            "TOTALSIZE" : 2916778,
            "USER" : "anotherexampleuser123456"
         },
         {
            "DEFERCOUNT" : 0,
            "DEFERFAILCOUNT" : 0,
            "DOMAIN" : "plankandexample.com",
            "FAILCOUNT" : 0,
            "OWNER" : "examplereseller",
            "PRIMARY_DOMAIN" : "plankandexample.com",
            "REACHED_MAXDEFERFAIL" : 0,
            "REACHED_MAXEMAILS" : 0,
            "SENDCOUNT" : 18,
            "SUCCESSCOUNT" : 22,
            "TOTALSIZE" : 113893594,
            "USER" : "exampleanotheruser234"
         },
         {
            "DEFERCOUNT" : 0,
            "DEFERFAILCOUNT" : 0,
            "DOMAIN" : "adgasdgadsexamplegasdgsdagsdg.com",
            "FAILCOUNT" : 0,
            "OWNER" : "examplereseller",
            "PRIMARY_DOMAIN" : "adgasdgadsexamplegasdgsdagsdg.com",
            "REACHED_MAXDEFERFAIL" : 0,
            "REACHED_MAXEMAILS" : 0,
            "SENDCOUNT" : 1,
            "SUCCESSCOUNT" : 1,
            "TOTALSIZE" : 1132,
            "USER" : "exampleuser123"
         }
      ]
   },
   "metadata" : {
      "__chunked" : 1,
      "command" : "emailtrack_user_stats",
      "overflowed" : 0,
      "reason" : "OK",
      "result" : 1,
      "version" : 1
   }
}
*/
type cpWhmapiResponseEmailTrackUserStats struct {
    Data struct {
        Records []struct {
            DeferCount         int    `json:"DEFERCOUNT"`
            DeferFailCount     int    `json:"DEFERFAILCOUNT"`
            Domain             string `json:"DOMAIN"`
            FailCount          int    `json:"FAILCOUNT"`
            Owner              string `json:"OWNER"`
            PrimaryDomain      string `json:"PRIMARY_DOMAIN"`
            ReachedMaxDeferFail json.RawMessage    `json:"REACHED_MAXDEFERFAIL"` //"REACHED_MAXDEFERFAIL" : "5/5 (100%)" OR "REACHED_MAXDEFERFAIL" : 0,
            ReachedMaxEmails   json.RawMessage    `json:"REACHED_MAXEMAILS"` //"REACHED_MAXEMAILS" : "150/150", OR "REACHED_MAXEMAILS" : 0,
            SendCount          int    `json:"SENDCOUNT"`
            SuccessCount       int    `json:"SUCCESSCOUNT"`
            TotalSize          int    `json:"TOTALSIZE"`
            User               string `json:"USER"`
        } `json:"records"`
    } `json:"data"`
    Metadata struct {
        Chunked   int    `json:"__chunked"`
        Command   string `json:"command"`
        Overflowed int    `json:"overflowed"`
        Reason    string `json:"reason"`
        Result    int    `json:"result"`
        Version   int    `json:"version"`
    } `json:"metadata"`
}

func getBandwidth(user string) int{
    var bw int
    var lines []string

    file, err := os.Open("/var/cpanel/bandwidth.cache/"+user)
    if err != nil {
        if debug {
            log.Println("failed opening file: %s", err)
        }
        return bw
    }

    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanLines)
    for scanner.Scan() {
        txty := scanner.Text()
        lines = append(lines,txty)
    }

    file.Close()

    out := strings.Join(lines,"\n")
    bw,_ = strconv.Atoi(out)

    return bw
}

func convertToFloat(value interface{}) (float64, error) {
    switch v := value.(type) {
    case int:
        return float64(v), nil
    case float64:
        return v, nil
    case string:
        return parseFloat(v)
    default:
        return 0, fmt.Errorf("unsupported type: %T", v)
    }
}

func parseFloat(s string) (float64, error) {
    return strconv.ParseFloat(s, 64)
}

func convertToString(value interface{}) (string, error) {
    switch v := value.(type) {
    case int, float64:
        return fmt.Sprintf("%v", v), nil
    case string:
        return v, nil
    default:
        return "", fmt.Errorf("unsupported type: %T", v)
    }
}

/*
Example quota output (Aug 18, 2023):
# /usr/bin/uapi Quota get_quota_info --user dummyuser2 --output=jsonpretty
{
   "func" : "get_quota_info",
   "module" : "Quota",
   "result" : {
      "status" : 1,
      "messages" : null,
      "metadata" : {},
      "data" : {
         "inodes_used" : 104,
         "inodes_remain" : "0",
         "megabyte_limit" : 1024,
         "under_megabyte_limit" : "1",
         "under_quota_overall" : "1",
         "megabytes_used" : 401.77,
         "under_inode_limit" : "1",
         "megabytes_remain" : 622.23,
         "inode_limit" : "0"
      },
      "errors" : null,
      "warnings" : null
   },
   "apiversion" : 3
}

# Sometimes it also comes out as strings:
# /usr/bin/uapi Quota get_quota_info --user paneltest1 --output=jsonpretty
{
   "func" : "get_quota_info",
   "apiversion" : 3,
   "result" : {
      "status" : 1,
      "messages" : null,
      "metadata" : {},
      "data" : {
         "under_quota_overall" : "1",
         "under_megabyte_limit" : "1",
         "megabyte_limit" : "0.00",
         "inodes_remain" : "0",
         "inodes_used" : 262,
         "inode_limit" : "0",
         "megabytes_remain" : "0.00",
         "under_inode_limit" : "1",
         "megabytes_used" : 7.13
      },
      "errors" : null,
      "warnings" : null
   },
   "module" : "Quota"
}

*/
func getQuota(user string) (string,string,float64){
    out := cpUapi(strings.TrimSpace(user),"Quota","get_quota_info")

    var resp UapiResponse
    err := json.Unmarshal(out, &resp)

    if err != nil {
        log.Println("error:", err)
        return "","",0
    }

    megabytesLimit, _ := convertToFloat(resp.Result.Data.MegabytesLimit)
    megabytesUsed, _ := convertToFloat(resp.Result.Data.MegabytesUsed)

    /*
    fmt.Println("Megabytes Limit (float64):", megabytesLimit)
    fmt.Println("Megabytes Used (float64):", megabytesUsed)
    */

    perc := float64(0)

    if(megabytesLimit>0){
        perc = math.Round((megabytesUsed/megabytesLimit) * 100)
    }

    // Converting to string if needed
    megabytesLimitStr, _ := convertToString(resp.Result.Data.MegabytesLimit)
    megabytesUsedStr, _ := convertToString(resp.Result.Data.MegabytesUsed)

    /*
    fmt.Println("Megabytes Limit (string):", megabytesLimitStr)
    fmt.Println("Megabytes Remain (string):", megabytesRemainStr)
    fmt.Println("Megabytes Used (string):", megabytesUsedStr)
    */

    return megabytesLimitStr, megabytesUsedStr, perc
}

// Function to get disk usage percentage metrics
func getDiskUsagePercent() cpWhmapiResponseDiskUsage {
    jsonStr := cpWhmapi("--output=jsonpretty", "getdiskusage")
    var response cpWhmapiResponseDiskUsage
    err := json.Unmarshal([]byte(jsonStr), &response)
    if err != nil {
        panic(err)
    }
    return response
}

// Function to get system load average metrics
func getSystemLoadAverage() cpWhmapiResponseLoadAverage {
    jsonStr := cpWhmapi("--output=jsonpretty", "systemloadavg")
    var response cpWhmapiResponseLoadAverage
    err := json.Unmarshal([]byte(jsonStr), &response)
    if err != nil {
        panic(err)
    }
    return response
}

// Function to get ram usage
func getSystemMemory() cpSystemMemory {
    jsonStr, err := getMemoryInfo()
    if err != nil {
        panic(err)
    }

    var response cpSystemMemory
    err = json.Unmarshal([]byte(jsonStr), &response)
    if err != nil {
        panic(err)
    }
    return response
}




//This function may need to be modified, assuming cPanel ends up providing different string unit names
//Was unable to determine what all strings they provide.
func convertToMB(value float64, unit string) float64 {
	unit = strings.ToUpper(unit)
	switch unit {
	case "KB":
		return value / 1024
	case "MB":
		return value
	case "GB":
		return value * 1024
	case "TB":
		return value * 1024 * 1024
	case "PB":
		return value * 1024 * 1024 * 1024
	case "B":
		return value / (1024 * 1024)
	case "BITS":
		return value / (1024 * 1024 * 8)
	default:
        log.Println("Unknown string value unit for convertToMB(), returning back value as zero: "+unit)
		return 0
	}
}

func getUserBandwidthLimitAndUsage(user string) (string,float64,float64,float64) {
    //uapi --output=jsonpretty --user=example StatsBar get_stats display='bandwidthusage'

    //Intentionally left out single quote on display= , so its processed properly via the function
    out := cpUapi(strings.TrimSpace(user),"StatsBar","get_stats", "display=bandwidthusage")
    
    var resp UapiResponseBandwidthUsage
    err := json.Unmarshal(out, &resp)

    if err != nil {
        log.Println("original bytes for json:", string(out))
        log.Println("user requested:", user)
        log.Println("error:", err)
        return "",0,0,0
    }

    // Declare the variables with default values
    unitsOfMeasurement := "MB"
    userBandwidthMax := 0.0
    userBandwidthUsed := 0.0
    userBandwidthUsedPercent := 0.0

    // Check if there is at least one element in the slice
    if len(resp.Result.Data) > 0 {
        unitsOfMeasurement, _ = convertToString(resp.Result.Data[0]["units"])
        userBandwidthMax, _ = convertToFloat(resp.Result.Data[0]["_max"])
        userBandwidthUsed, _ = convertToFloat(resp.Result.Data[0]["_count"])
        userBandwidthUsedPercent, _ = convertToFloat(resp.Result.Data[0]["percent"])
    }

    /*
    fmt.Println("User (string):", user)
    fmt.Println("Units of Measurement (string):", unitsOfMeasurement)
    fmt.Println("User Bandwidth Max (float64):", userBandwidthMax)
    fmt.Println("User Bandwidth Used (float64):", userBandwidthUsed)
    fmt.Println("User Bandwidth Used Percent (float64):", userBandwidthUsedPercent)
    */

    //Convert to MB
	userBandwidthUsedMB := convertToMB(userBandwidthUsed, unitsOfMeasurement)
	userBandwidthMaxMB := convertToMB(userBandwidthMax, unitsOfMeasurement)

    //Round value
	userBandwidthUsedMB = math.Round(userBandwidthUsedMB*100) / 100
	userBandwidthMaxMB = math.Round(userBandwidthMaxMB*100) / 100
    
    return "MB", userBandwidthMaxMB, userBandwidthUsedMB, userBandwidthUsedPercent
}

func cpUapi(user string,commands ...string) []byte{
    var com []string
    com = append(com,"--user="+user)
    com = append(com,"--output=json")
    for _,c:= range commands {
        com = append(com,c)
    }

    //log.Println("[DEBUG] Running com: /usr/bin/uapi " + strings.Join(com, " "))
    out, err := exec.Command("/usr/bin/uapi",com...).CombinedOutput()
    if err != nil {
        log.Println(err)
        return []byte("")
    }

    return out
}


// Perform whmapi1 API call
func cpWhmapi(commands ...string) []byte{
    var com []string
    for _,c:= range commands {
        com = append(com,c)
    }

    //log.Println("[DEBUG] Running com: /usr/bin/uapi " + strings.Join(com, " "))
    out, err := exec.Command("/usr/sbin/whmapi1",com...).CombinedOutput()
    if err != nil {
        log.Println(err)
        return []byte("")
    }

    return out
}

// Get email incoming and outgoing counts
/*
func eximMailCounts() (string, error) {
	incomingCmd := "grep \"<=\" /var/log/exim_mainlog | grep -v \"example.com\" | grep \"$(date +'%Y-%m-%d')\" | wc -l"
	outgoingCmd := "grep \"=>\" /var/log/exim_mainlog | grep -v \"example.com\" | grep \"$(date +'%Y-%m-%d')\" | wc -l"

	incomingCount, err := runAndParseCountExim(incomingCmd)
	if err != nil {
        log.Printf("Error empty result eximMailCounts() incomingCount\n", err)
		return "", err
	}

	outgoingCount, err := runAndParseCountExim(outgoingCmd)
	if err != nil {
        log.Printf("Error empty result eximMailCounts() outgoingCount\n", err)
		return "", err
	}

	result := map[string]interface{}{
		"incoming": incomingCount,
		"outgoing": outgoingCount,
	}

	jsonResult, err := json.Marshal(result)
	if err != nil {
		log.Printf("Error while creating JSON result: %v\n", err)
		return "", err
	}

	return string(jsonResult), nil
}
*/

/*
func runAndParseCountExim(cmd string) (int, error) {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
    //log.Printf("runAndParseCount result: %s\n", out)
	if err != nil {
		log.Printf("Error while running command: %v\n", err)
		return 0, err
	}

	countStr := strings.TrimSpace(string(out))
	count, err := strconv.Atoi(countStr)
	if err != nil {
		log.Printf("Error while parsing count: %v\n", err)
		return 0, err
	}

	return count, nil
}
*/

func getMemoryInfo() (string, error) {
    //The below is the go implementation of doing:
    //free -m | awk '/Mem:/ {printf "{\"total\": %s, \"used\": %s, \"free\": %s, \"shared\": %s, \"buff/cache\": %s, \"available\": %s}", $2, $3, $4, $5, $6, $7}'
	cmd := exec.Command("free", "-m")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("Invalid 'free -m' output")
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 7 {
		return "", fmt.Errorf("Invalid 'free -m' output")
	}

	memoryInfo := map[string]int{
		"total":     strToInt(fields[1]),
		"used":      strToInt(fields[2]),
		"free":      strToInt(fields[3]),
		"shared":    strToInt(fields[4]),
		"buff/cache": strToInt(fields[5]),
		"available": strToInt(fields[6]),
	}

	jsonData, err := json.Marshal(memoryInfo)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// Function to get email user stats
func getCPanelEmailTrackUserStats() cpWhmapiResponseEmailTrackUserStats {
	// Get the current time in UTC
	now := time.Now().UTC()

    // Create a new time object for the start of the day in UTC
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Get the Unix timestamp for the start of the day
	unixTimestamp := startOfDay.Unix()

	// Convert Unix timestamp to string
	startOfDayStr := fmt.Sprintf("%d", unixTimestamp)

    jsonStr := cpWhmapi("--output=jsonpretty", "emailtrack_user_stats", "starttime=" + startOfDayStr)
    var response cpWhmapiResponseEmailTrackUserStats
    err := json.Unmarshal([]byte(jsonStr), &response)
    if err != nil {
        panic(err)
    }
    return response
}

// Function to get system load average metrics
func getCPanelHostname() cpWhmapiResponseHostname {
    jsonStr := cpWhmapi("--output=jsonpretty", "gethostname")
    var response cpWhmapiResponseHostname
    err := json.Unmarshal([]byte(jsonStr), &response)
    if err != nil {
        panic(err)
    }
    return response
}

func extractHostnameDomain(input string) string {
    // Check if the input is an IP address
    if net.ParseIP(input) != nil {
        return "" // If it's an IP, return a blank result
    }

    parts := strings.Split(input, ".")
    if len(parts) >= 2 {
        return parts[len(parts)-2] + "." + parts[len(parts)-1]
    }

    return ""
}

func getEximLogIncomingMailCount() (int, error) {
    //sudo grep "<=" /var/log/exim_mainlog | grep -v "cpanelhostnamehere.com" | grep "$(date +'%Y-%m-%d')"
    cPanelHostname := getCPanelHostname()
    domainExclude := extractHostnameDomain(cPanelHostname.Data.Hostname)
    //log.Println("Domain Exclude Incoming: " + domainExclude)
    cmdStr := "grep '<=' /var/log/exim_mainlog | grep -v '" + domainExclude + "' | grep \"$(date +'%Y-%m-%d')\" | wc -l"
    cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
    outputStr := strings.TrimSpace(string(output))
    //log.Println("Incoming mail count: " + outputStr)
    //log.Println("Incoming mail cmd: " + cmdStr)
	if err != nil {
		return 0, err
	}

    // Check if the trimmed output is empty and convert it to zero
    if outputStr == "" {
        return 0, nil
    }

	return strToInt(outputStr), nil
}

func getEximLogOutgoingMailCount() (int, error) {
    //sudo grep "=>" /var/log/exim_mainlog | grep -v "cpanelhostnamehere.com" | grep "$(date +'%Y-%m-%d')"
    cPanelHostname := getCPanelHostname()
    domainExclude := extractHostnameDomain(cPanelHostname.Data.Hostname)
    //log.Println("Domain Exclude Outgoing: " + domainExclude)
    cmdStr := "grep '=>' /var/log/exim_mainlog | grep -v '" + domainExclude + "' | grep \"$(date +'%Y-%m-%d')\" | wc -l"
    cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
    outputStr := strings.TrimSpace(string(output))
    //log.Println("Outgoing mail count: " + outputStr)
    //log.Println("Outgoing mail cmd: " + cmdStr)
	if err != nil {
		return 0, err
	}

    // Check if the trimmed output is empty and convert it to zero
    if outputStr == "" {
        return 0, nil
    }

	return strToInt(outputStr), nil
}

func strToInt(s string) int {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil {
		return 0
	}
	return result
}

func getFTP() []string{
    var lines []string
    file, err := os.Open("/etc/proftpd/passwd.vhosts")
    if err != nil {
        if debug {
            log.Println("failed opening file: %s", err)
        }
        return lines
    }

    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanLines)

    for scanner.Scan() {
        txty := scanner.Text()
        parts := strings.Split(txty,":")
        if(len(parts)>0){
        lines = append(lines,parts[0])
        }
    }
    file.Close()

    return lines
}

func getEmails() []string{
    var email []string
    var wg = sizedwaitgroup.New(100)
    files := getFilesInDir("/var/cpanel/users")
    for _,f := range files {
        wg.Add()
        go func(f string){
            defer wg.Done()
            user := filepath.Base(f)
            matches := matchFileLine(f,"^DNS")

            for _,m := range matches {
                parts := strings.Split(m,"=")
                if(len(parts)>0) {
                    dom := parts[1]
                    // log.Println("Looking in","/home/"+user+"/mail/"+dom)
                    fldfs := getFilesInDir("/home/"+user+"/mail/"+dom)
                    for _,fl := range fldfs {
                        eu := filepath.Base(fl)
                        //  log.Println("Email Dir",fl)
                        if(eu!="cur" && eu!="new" && eu!="tmp" && eu!="") {
                            email = append(email,eu+"@"+dom)
                        }
                    }
                }
            }
        }(f)
    }
    wg.Wait()
    return email
}

func getPlans() (map[string]int){
    var plans = make(map[string]int)
    files := getFilesInDir("/var/cpanel/users")
    matches := matchFilesLine(files,"PLAN=.*",true)

    for _,m := range matches {
        parts := strings.Split(m,"=")
        if(len(parts)>0){
            plans[parts[1]]++
        }
    }

    return plans
}

func matchFileLine(f string,regx string) map[string]string{ 
    var lines = make(map[string]string)
    file, err := os.Open(f)

    if err != nil {
        if debug {
            log.Println("failed opening file: %s", err)
        }
        return lines
    }

    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanLines)

    for scanner.Scan() {
        txty := scanner.Text()
        matched, _ := regexp.MatchString(regx, txty)
        if(matched==true){
            lines[f]=txty
        }
    }

    file.Close()
    return lines
}

func matchFilesLine(files []string,regx string, stopatfirst bool) map[string]string{
    var lines = make(map[string]string)

    for _,f := range files {
        file, err := os.Open(f)

        if err != nil {
            if debug {
                log.Println("failed opening file: %s", err)
            }
            continue
        }

        scanner := bufio.NewScanner(file)
        scanner.Split(bufio.ScanLines)

        for scanner.Scan() {
            txty := scanner.Text()
            matched, _ := regexp.MatchString(regx, txty)
            if(matched==true) {
                lines[f]=txty
                if(stopatfirst==true){
                    break
                }
            }
        }

        file.Close()

    }

    return lines
}


func getSessions(web string) int{
    files := getFilesInDir("/var/cpanel/sessions/raw")
    
    var wctr int
    var ectr int
    
    for _,f := range files {
        if(strings.Contains(f,"@")) {
            ectr++
        } else if(!strings.Contains(f,"_dav_")) {
            wctr++
        }
    }
    
    if(web=="web") {
        return wctr
    }
    
    return ectr
}

func getRelease() (string){
    file, err := os.Open("/etc/cpupdate.conf")

    if err != nil {
        if debug {
            log.Println("failed opening file: %s", err)
        }
        return ""
    }

    defer file.Close()

    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanLines)

    for scanner.Scan() {
        txty := scanner.Text()
        if(strings.Contains(txty,"CPANEL=")){
            parts := strings.Split(txty,"=")
            if(len(parts)>0){
                return parts[1]
            }
        }
    }

    return "" 
}

func getDomains() ([]string){
    var domains []string

    file, err := os.Open("/etc/userdomains")

    if err != nil {
        if debug {
            log.Println("failed opening file: %s", err)
        }
        return domains
    }

    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanLines)


    for scanner.Scan() {
        txty := scanner.Text()
        parts := strings.Split(txty,":")

        if(len(parts)>1){
            domains = append(domains,parts[0])
        }
    }

    file.Close()
    return domains
}

func getFilesInDir(root string) []string{
    var files []string
    /*
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        files = append(files, path)
        return nil
    })
    if err != nil {
        log.Println(err)
        
    }*/
    
    filer, err := ioutil.ReadDir(root)
    
    if err != nil {
        if debug {
            log.Println(err)
        }
        return files
    }
    
    for _, f := range filer {
        files = append(files,root+"/"+f.Name())
    }
 
    return files
}





