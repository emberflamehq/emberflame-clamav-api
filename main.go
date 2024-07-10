package main

import (
	// "bytes"
	"context"
	"encoding/json"
	"fmt"
	// "html/template"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	log "github.com/charmbracelet/log"
	// "github.com/fatih/structs"
	"github.com/gorilla/mux"
	
	"github.com/malice-plugins/pkgs/utils"
	"github.com/parnurzeal/gorequest"
	// "github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	name     = "clamav"
	category = "av"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	path string
)

type pluginResults struct {
	ID   string      `json:"id" structs:"id,omitempty"`
	Data ResultsData `json:"clamav" structs:"clamav"`
}

// ClamAV json object
type ClamAV struct {
	Results ResultsData `json:"clamav"`
}

// ResultsData json object
type ResultsData struct {
	Infected bool   `json:"infected" structs:"infected"`
	Result   string `json:"result" structs:"result"`
	Engine   string `json:"engine" structs:"engine"`
	Known    string `json:"known" structs:"known"`
	Updated  string `json:"updated" structs:"updated"`
	Error    string `json:"error" structs:"error"`
	MarkDown string `json:"markdown,omitempty" structs:"markdown,omitempty"`
}



func assert(err error) {
	if err != nil {
		// ClamAV exits with error status 1 if it finds a virus
		if err.Error() != "exit status 1" {
			// log.WithFields(log.Fields{
			// 	"plugin":   name,
			// 	"category": category,
			// 	"path":     path,
			// }).Fatal(err)
			log.Error(err)
		}
	}
}

// RunCommand runs cmd on file
func RunCommand(ctx context.Context, cmd string, args ...string) (string, error) {

	var c *exec.Cmd

	if ctx != nil {
		c = exec.CommandContext(ctx, cmd, args...)
	} else {
		c = exec.Command(cmd, args...)
	}

	output, err := c.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	// check for exec context timeout
	if ctx != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("command %s timed out", cmd)
		}
	}

	return string(output), nil
}

// AvScan performs antivirus scan
func AvScan(timeout int) ClamAV {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	results, err := utils.RunCommand(ctx, "/usr/bin/clamscan", "--stdout", path)
	assert(err)
	log.Info("clamav cli results", results)
	return ClamAV{
		Results: ParseClamAvOutput(results, nil),
	}
}

// ParseClamAvOutput convert clamav output into ClamAV struct
func ParseClamAvOutput(clamout string, err error) ResultsData {

	if err != nil {
		return ResultsData{Error: err.Error()}
	}

	// log.WithFields(log.Fields{
	// 	"plugin":   name,
	// 	"category": category,
	// 	"path":     path,
	// }).Debug("ClamAV Output: ", clamout)
	log.Info("ClamAV Output: ", clamout)

	clamAV := ResultsData{}

	lines := strings.Split(clamout, "\n")
	// Extract AV Scan Result
	result := lines[0]
	if len(result) != 0 {
		pathAndResult := strings.Split(result, ":")
		if strings.Contains(pathAndResult[1], "OK") {
			clamAV.Infected = false
		} else {
			clamAV.Infected = true
			clamAV.Result = strings.TrimSpace(strings.TrimRight(pathAndResult[1], "FOUND"))
		}
	} else {
		fmt.Println("[ERROR] empty scan result: ", result)
		// os.Exit(2)
		return clamAV
	}
	// Extract Clam Details from SCAN SUMMARY
	for _, line := range lines[1:] {
		// log.Info("line", line)
		if len(line) != 0 {
			keyvalue := strings.Split(line, ":")
			if len(keyvalue) != 0 {
				switch {
				case strings.Contains(keyvalue[0], "Known viruses"):
					log.Info("i am in known viruses", line)
					clamAV.Known = strings.TrimSpace(keyvalue[1])
				case strings.Contains(line, "Engine version"):
					log.Info("i am in engine version", line)
					clamAV.Engine = strings.TrimSpace(keyvalue[1])
				}
			}
		}
	}
	updatedDate := string(getUpdatedDate())
	log.Info("Get updated date", string(updatedDate))
	clamAV.Updated = updatedDate

	return clamAV
}

func updateAV(ctx context.Context) error {
	filePath := "/opt/malice/UPDATED"
	fmt.Println("Updating ClamAV...")
	log.Info("Updating ClamAV signatures")
	fmt.Println(utils.RunCommand(ctx, "freshclam"))
	log.Info("Finished updating virus signatures")
	// fmt.Println(utils.RunCommand(ctx, "service clamav-daemon restart"))

	// In the future if i need to update the binary
	// log.Info("Attempting to update clamav binary")
	// cmdUpdate := exec.Command("sudo", "apt-get", "upgrade", "clamav", "-y")
	// cmdUpdate := exec.Command("service", "clamav-daemon", "restart")
	// output, err := cmdUpdate.CombinedOutput()
	// if err != nil {
	// 	log.Info("Error running apt-get update:", err)
	// 	return err
	// }
	// log.Info("apt-get update output:", string(output))
	
	t := time.Now().Format("20060102")

	// Open the file for writing (creating it if it doesn't exist, and truncating it if it does)
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return err
	}
	defer file.Close()

	// Write the formatted time to the file
	_, err = file.WriteString(t)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return err
	}
	log.Info("Completed writing to file")
	return err
}

func getUpdatedDate() string {
	log.Info("In getUpdatedDate")
	filePath := "/opt/malice/UPDATED"
	data, err := ioutil.ReadFile(filePath)
    if err != nil {
        log.Error("failed reading data from file: %s", err)
		return "Could not read updated file"
    }
	return string(data)
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func webService() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/scan", webAvScan).Methods("POST")
	// router.HandleFunc("/update", updateAvScan).Methods("POST")
	log.Info("web service listening on port :3992")
	log.Fatal(http.ListenAndServe(":3992", router))
}

// func updateAvScan(w http.ResponseWriter, r *http.Request) {
// 	_, err := updateAv();
// }
func webAvScan(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("malware")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Please supply a valid file to scan.")
		log.Error(err)
	}
	defer file.Close()

	log.Debug("Uploaded fileName: ", header.Filename)

	tmpfile, err := ioutil.TempFile("/malware", "web_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	data, err := ioutil.ReadAll(file)
	assert(err)
	log.Info("file data", string(data))
	if _, err = tmpfile.Write(data); err != nil {
		log.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	// Do AV scan
	path = tmpfile.Name()
	clamav := AvScan(60)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	log.Info("clamav info", clamav)
	if err := json.NewEncoder(w).Encode(clamav); err != nil {
		log.Fatal(err)
	}
}

func main() {
	log.SetLevel(log.DebugLevel)
	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "clamav"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice ClamAV Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.BoolFlag{
			Name:   "callback, c",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  60,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "Update virus definitions",
			Action: func(c *cli.Context) error {
				ctx, cancel := context.WithTimeout(
					context.Background(),
					time.Duration(c.GlobalInt("timeout"))*time.Second,
				)
				defer cancel()

				return updateAV(ctx)
			},
		},
		{
			Name:  "web",
			Usage: "Create a ClamAV scan web service",
			Action: func(c *cli.Context) error {
				webService()
				return nil
			},
		},
	}
	app.Action = func(c *cli.Context) error {

		var err error

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, err = filepath.Abs(c.Args().First())
			assert(err)

			if _, err = os.Stat(path); os.IsNotExist(err) {
				assert(err)
			}

			clamav := AvScan(c.Int("timeout"))
			// clamav.Results.MarkDown = generateMarkDownTable(clamav)

			if c.Bool("table") {
				fmt.Println(clamav.Results.MarkDown)
			} else {
				// convert to JSON
				clamav.Results.MarkDown = ""
				clamavJSON, err := json.Marshal(clamav)
				assert(err)
				if c.Bool("post") {
					request := gorequest.New()
					if c.Bool("proxy") {
						request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
					}
					request.Post(os.Getenv("MALICE_ENDPOINT")).
						Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", utils.GetSHA256(path))).
						Send(string(clamavJSON)).
						End(printStatus)

					return nil
				}
				fmt.Println(string(clamavJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a file to scan with malice/clamav"))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}