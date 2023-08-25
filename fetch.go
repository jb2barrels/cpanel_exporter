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
        log.Println(err)
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

func getBandwidth(user string) int{
    var bw int
    var lines []string

    file, err := os.Open("/var/cpanel/bandwidth.cache/"+user)
    if err != nil {
        log.Println("failed opening file: %s", err)
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

func cpUapi(user string,commands ...string) []byte{
    var com []string
    com = append(com,"--user="+user)
    com = append(com,"--output=json")
    for _,c:= range commands {
        com = append(com,c)
    }

    out, err := exec.Command("/usr/bin/uapi",com...).CombinedOutput()
    if err != nil {
        log.Println(err)
        return []byte("")
    }

    return out
}



func getFTP() []string{
    var lines []string
    file, err := os.Open("/etc/proftpd/passwd.vhosts")
    if err != nil {
        log.Println("failed opening file: %s", err)
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
        log.Println("failed opening file: %s", err)
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
            log.Println("failed opening file: %s", err)
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
        log.Println("failed opening file: %s", err)
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
        log.Println("failed opening file: %s", err)
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
        log.Println(err)
        return files
    }
    
    for _, f := range filer {
        files = append(files,root+"/"+f.Name())
    }
 
    return files
}





