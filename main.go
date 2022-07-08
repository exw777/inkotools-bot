package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/go-ping/ping"
	"github.com/mitchellh/mapstructure"
	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// CFGFILE - path to config file
const CFGFILE string = "config/main.yml"

// Config struct
type Config struct {
	BotToken     string `yaml:"bot_token"`
	UseWebhook   bool   `yaml:"use_webhook"`
	WebhookURL   string `yaml:"webhook_url"`
	ListenPort   string `yaml:"listen_port"`
	Admin        int64  `yaml:"admin"`
	InkoToolsAPI string `yaml:"inkotools_api_url"`
	GraydbURL    string `yaml:"graydb_url"`
	DebugMode    bool   `yaml:"debug"`
}

// UserConfig struct
type UserConfig struct {
	Name            string `yaml:"name"`
	Token           string `yaml:"token"`
	Username        string `yaml:"username"` // returned from api by token, saved for templates
	RefreshEnabled  bool   `yaml:"refresh_enabled"`
	RefreshInterval string `yaml:"refresh_interval"`
	RefreshStart    string `yaml:"refresh_start"`
	RefreshStop     string `yaml:"refresh_stop"`
	NotifyNew       bool   `yaml:"notify_new"`
	NotifyUpdate    bool   `yaml:"notify_update"`
}

// UserData struct
type UserData struct {
	Mode    string // command mode
	TMP     string // to save temporary data between messages
	Cron    map[string]cron.EntryID
	Tickets Tickets
}

// Tickets struct
type Tickets struct {
	Data []Ticket `mapstructure:"data"`
	Meta struct {
		User string `mapstructure:"username"`
	} `mapstructure:"meta"`
	Updated time.Time
}

// Cron - cron object
var Cron *cron.Cron

// Data - data object
var Data map[int64]*UserData

// CFG - config object
var CFG Config

// Users - users config
var Users map[int64]*UserConfig

// TPL - templates object
var TPL *template.Template

// Bot - bot object
var Bot *tgbotapi.BotAPI

// Pingers - map of active pingers, key is uid
var Pingers map[int64]ping.Pinger

// Switch type
type Switch struct {
	IP       string `mapstructure:"ip"`
	Location string `mapstructure:"location"`
	MAC      string `mapstructure:"mac"`
	Model    string `mapstructure:"model"`
	Status   bool   `mapstructure:"status"`
}

// PortSummary type
type PortSummary struct {
	Style      string
	Slots      []Port
	LinkUp     bool
	PortNumber int
	Bandwidth  PortBandwidth
	Counters   struct {
		PortCounters `mapstructure:",squash"`
		Error        string
	}
	VLAN struct {
		PortVlan `mapstructure:",squash"`
		Error    string
	}
	ACL struct {
		Entries []PortACL
		Error   string
	}
	Multicast struct {
		PortMulticast `mapstructure:",squash"`
		Error         string
	}
	MAC struct {
		Entries []PortMac
		Error   string
	}
	ARP struct {
		Entries []ARPEntry
		Error   string
	}
}

// Port type
type Port struct {
	Port          int    `mapstructure:"port"`
	Type          string `mapstructure:"type"`
	State         bool   `mapstructure:"state"`
	Speed         string `mapstructure:"speed"`
	Link          bool   `mapstructure:"link"`
	Status        string `mapstructure:"status"`
	Learning      bool   `mapstructure:"learning"`
	Autodowngrade bool   `mapstructure:"autodowngrade"`
	Description   string `mapstructure:"desc"`
	Cable         []Pair `mapstructure:"cable"`
	DDM           struct {
		Temperature float32 `mapstructure:"temperature"`
		Voltage     float32 `mapstructure:"voltage"`
		BiasCurrent float32 `mapstructure:"bias_current"`
		PowerTX     float32 `mapstructure:"tx_power"`
		PowerRX     float32 `mapstructure:"rx_power"`
	} `mapstructure:"ddm"`
}

// Pair type - pair in cable
type Pair struct {
	Pair  int    `mapstructure:"pair"`
	State string `mapstructure:"state"`
	Len   int    `mapstructure:"len"`
}

// PortBandwidth limits type
type PortBandwidth struct {
	RX uint `mapstructure:"rx"`
	TX uint `mapstructure:"tx"`
}

// PortCounters type
type PortCounters struct {
	TotalRX  uint        `mapstructure:"rx_total"`
	TotalTX  uint        `mapstructure:"tx_total"`
	SpeedRX  uint        `mapstructure:"rx_speed"`
	SpeedTX  uint        `mapstructure:"tx_speed"`
	ErrorsRX []PortError `mapstructure:"rx_errors"`
	ErrorsTX []PortError `mapstructure:"tx_errors"`
}

// PortError type
type PortError struct {
	Name  string `mapstructure:"name"`
	Count int    `mapstructure:"count"`
}

// PortVlan type
type PortVlan struct {
	Port     int   `mapstructure:"port"`
	Untagged []int `mapstructure:"untagged"`
	Tagged   []int `mapstructure:"tagged"`
}

// PortMac type
type PortMac struct {
	Port   int    `mapstructure:"port"`
	VlanID int    `mapstructure:"vid"`
	Mac    string `mapstructure:"mac"`
}

// PortACL type
type PortACL struct {
	Port      int    `mapstructure:"port"`
	ProfileID int    `mapstructure:"profile_id"`
	AccessID  int    `mapstructure:"access_id"`
	IP        string `mapstructure:"ip"`
	Mask      string `mapstructure:"mask"`
	Mode      string `mapstructure:"mode"`
}

// PortMulticast type
type PortMulticast struct {
	SourcePorts []int `mapstructure:"source"`
	MemberPorts []int `mapstructure:"member"`
	State       bool
	Groups      []string
	Filters     []string
}

// IPCalc type
type IPCalc struct {
	IP      string `mapstructure:"ip"`
	Mask    string `mapstructure:"mask"`
	Gateway string `mapstructure:"gateway"`
	Prefix  int    `mapstructure:"prefix"`
}

// ARPEntry type
type ARPEntry struct {
	IP     string `mapstructure:"ip"`
	Mac    string `mapstructure:"mac"`
	VlanID int    `mapstructure:"vid"`
	State  bool   `mapstructure:"state"`
}

// DBSearch type
type DBSearch struct {
	Data []Switch `mapstructure:"data"`
	Meta struct {
		Entries struct {
			Current int `mapstructure:"current"`
			PerPage int `mapstructure:"per_page"`
			Total   int `mapstructure:"total"`
		} `mapstructure:"entries"`
		Pages struct {
			Current int `mapstructure:"current"`
			Total   int `mapstructure:"total"`
		} `mapstructure:"pages"`
	} `mapstructure:"meta"`
}

// Contract type
type Contract struct {
	ContractID string   `mapstructure:"contract_id"`
	ClientID   uint     `mapstructure:"client_id"`
	Terminated bool     `mapstructure:"terminated"`
	Name       string   `mapstructure:"name"`
	Contacts   []string `mapstructure:"contact_list"`
	City       string   `mapstructure:"city"`
	Street     string   `mapstructure:"street"`
	House      string   `mapstructure:"house"`
	Room       string   `mapstructure:"room"`
	Company    string   `mapstructure:"company"`
	Office     string   `mapstructure:"office"`
	SwitchIP   string   `mapstructure:"sw_ip"`
	Port       string   `mapstructure:"port"`
	Cable      string   `mapstructure:"cable_length"`
	Comment    string   `mapstructure:"comment"`
	Billing    struct {
		Inet  InetAccount    `mapstructure:"internet"`
		Tel   TelAccount     `mapstructure:"telephony"`
		LDTel TelAccount     `mapstructure:"ld_telephony"`
		TV    BillingAccount `mapstructure:"television"`
	} `mapstructure:"billing_accounts"`
	Tickets []Ticket `mapstructure:"tickets`
}

// BillingAccount type
type BillingAccount struct {
	ID       int      `mapstructure:"account_id"`
	Services []string `mapstructure:"services"`
	Balance  float32  `mapstructure:"balance"`
	Credit   float32  `mapstructure:"credit"`
	Enabled  bool     `mapstructure:"enabled"`
}

// InetAccount type
type InetAccount struct {
	BillingAccount `mapstructure:",squash"`
	Tariff         string   `mapstructure:"tariff"`
	IPs            []string `mapstructure:"ip_list"`
	Speed          string   `mapstructure:"speed"`
}

// TelAccount type
type TelAccount struct {
	BillingAccount `mapstructure:",squash"`
	Numbers        []string `mapstructure:"number_list"`
}

// Ticket type
type Ticket struct {
	TicketID   int             `mapstructure:"ticket_id"`
	ContractID string          `mapstructure:"contract_id"`
	Creator    string          `mapstructure:"creator"`
	Created    time.Time       `mapstructure:"date"`
	Issue      string          `mapstructure:"issue"`
	Master     string          `mapstructure:"master"`
	Comments   []TicketComment `mapstructure:"comments"`
	Name       string          `mapstructure:"name"`
	Address    string          `mapstructure:"address"`
	Contacts   []string        `mapstructure:"contacts"`
	Modified   bool
	Tag        string
}

// TicketComment type
type TicketComment struct {
	Time    time.Time `mapstructure:"time"`
	Author  string    `mapstructure:"author"`
	Comment string    `mapstructure:"comment"`
}

// ColorReset - ANSI color
const ColorReset string = "\033[0m"

// ColorRed - ANSI color
const ColorRed string = "\033[31m"

// ColorGreen - ANSI color
const ColorGreen string = "\033[32m"

// ColorYellow - ANSI color
const ColorYellow string = "\033[33m"

// ColorBlue - ANSI color
const ColorBlue string = "\033[34m"

// ColorPurple - ANSI color
const ColorPurple string = "\033[35m"

// ColorCyan - ANSI color
const ColorCyan string = "\033[36m"

// ColorWhite - ANSI color
const ColorWhite string = "\033[37m"

// HELPUSER - help string for user
const HELPUSER string = `
<b>Raw parsing</b>
By default bot try to parse raw input:

<code>{CLIENT_IP|CONTRACT_ID}</code> - get client summary from gray database

<code>SW_IP</code> - get switch summary

<code>SW_IP PORT</code> - get short switch and short port summary with additional callback buttons:

<code>full/short</code> - switch between full and short port summary
<code>refresh</code> - update information in the same message
<code>repeat</code> - send new message with updated information
<code>clear</code> - clear port counters and refresh

<b><i>IP</i></b> can be in short or full format (e.g. <code>59.75</code> and <code>192.168.59.75</code> are equal)
For client's public ip you must specify address in full format.

Otherwise, the input is interpreted as a search query. You can search switches by mac, model or location.
Results will be paginated. Use callback buttons to navigate between pages: first, previous, next, last. 

<b>Available commands:</b>
<code>/help</code> - print this help
<code>/config</code> - edit user settings
<code>/tickets</code> - show tickets from gray database
<code>/ping HOST</code> - ping host
<code>/calc IP</code> - ip calculator (ip, mask, gateway, prefix)

`

// HELPADMIN - help string for admin
const HELPADMIN string = `
<code>list</code> - list authorized users
<code>add ID [NAME]</code> - add user with id <b><i>ID</i></b> and optional mark with comment <b><i>NAME</i></b>
<code>del ID</code> - delete user with id <b><i>ID</i></b>
<code>send ID TEXT</code> - send message <b><i>TEXT</i></b> to user with id <b><i>ID</i></b>
<code>broadcast TEXT</code> - send broadcast message <b><i>TEXT</i></b> 
<code>reload</code> - reload configuration from file
`

// UserTags - icons for custom user tags in tickets
const UserTags string = "🆕:⚒:🚨:👁‍🗨:📟:🔫:🪜:🪡:🧵:🛅:🌀:🔐:🌚:🕑:✅"

// BotCommands const
var BotCommands = []tgbotapi.BotCommand{
	{
		Command:     "tickets",
		Description: "show gray database tickets",
	},
	{
		Command:     "config",
		Description: "edit user settings",
	},
	{
		Command:     "help",
		Description: "print help",
	},
}

// HELPER FUNCTIONS

// check if uid is in users map
func userIsAuthorized(id int64) bool {
	_, ok := Users[id]
	return ok
}

// search int in list of int
func intInList(val int, lst []int) bool {
	sort.Ints(lst)
	idx := sort.SearchInts(lst, val)
	return !((idx == len(lst)) || (val != lst[idx]))
}

// split first arg from args
func splitArgs(args string) (first string, other string) {
	a := strings.SplitN(args, " ", 2)
	if len(a) < 2 {
		return a[0], ""
	}
	return a[0], strings.TrimSpace(a[1])
}

// split last arg from args
func splitLast(args string) (before string, last string) {
	i := strings.LastIndex(args, " ")
	return args[:i], args[i+1:]
}

// convert x.x --> 192.168.x.x, return empty string on invalid ip
func fullIP(ip string, isSwitch bool) string {
	octet := `[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]`
	reFull, _ := regexp.Compile(`^((` + octet + `)\.){3}(` + octet + `)$`)
	reShort, _ := regexp.Compile(`^(` + octet + `)\.(` + octet + `)$`)
	reSwitch, _ := regexp.Compile(`^192\.168\.(4[79]|5[7-9]|60)\.(` + octet + `)$`)
	if reShort.MatchString(ip) {
		ip = "192.168." + ip
	}
	if isSwitch && reSwitch.MatchString(ip) || !isSwitch && reFull.MatchString(ip) {
		return ip
	}
	return ""
}

// check if string is contract id
func isContract(s string) bool {
	rgx, _ := regexp.Compile(`^[0-9]{5}$`)
	return rgx.MatchString(s)
}

// print error in message
func fmtErr(e string) string {
	return "\n<b>ERROR</b>&#8252;\n<code>" + e + "</code>\n"
}

// print object formatted with template
func fmtObj(obj interface{}, tpl string) string {
	var buf bytes.Buffer
	TPL.ExecuteTemplate(&buf, tpl, obj)
	return buf.String()
}

// print bytes in human readable format
func fmtBytes(bytes uint, toBits bool) string {
	var ratio float64 = 1024
	units := [5]string{"B", "KB", "MB", "GB", "TB"}
	if toBits {
		ratio = 1000
		units = [5]string{"bit", "Kbit", "Mbit", "Gbit", "Tbit"}
		bytes *= 8
	}
	res := float64(bytes)
	i := 0
	for ; res >= ratio && i < len(units)-1; i++ {
		res /= ratio
	}
	return fmt.Sprintf("%.2f %s", res, units[i])
}

// print rounded duration if it is less than 100s.
func fmtRTT(d time.Duration) string {
	scale := 100 * time.Second
	// look for the max scale that is smaller than d
	for scale > d {
		scale = scale / 10
	}
	return d.Round(scale / 100).String()
}

// format phone number
func fmtPhone(s string) string {
	reNonDigit, _ := regexp.Compile(`\D`)
	reLocal, _ := regexp.Compile(`^6\d{6}$`)
	reMobile, _ := regexp.Compile(`^(?:[78]?)(\d{3})(\d{3})(\d{2})(\d{2})$`)
	// remove non-digit symbols
	res := reNonDigit.ReplaceAllString(s, "")
	// convert local number
	if reLocal.MatchString(res) {
		res = "8496" + res
	}
	// format as 8 (xxx) xxx-xx-xx
	m := reMobile.FindStringSubmatch(res)
	if len(m) > 1 {
		res = fmt.Sprintf("8(%s)%s-%s-%s", m[1], m[2], m[3], m[4])
		return res
	}
	// return raw if no matches
	return s
}

// format address for short template
func fmtAddress(s string) string {
	re, _ := regexp.Compile(`Коломна |ул\. |д\. |п\. \d+ |э\. \d+ |офис/цех\. | 0`)
	return re.ReplaceAllString(s, "")
}

// mapstructure decode with custom date format
func mapstructureDecode(input interface{}, output interface{}) {
	config := mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeHookFunc(time.RFC3339),
		Result:     &output,
	}
	decoder, _ := mapstructure.NewDecoder(&config)
	decoder.Decode(input)
}

// debug log
func logDebug(msg string) {
	if CFG.DebugMode {
		log.Printf("[%sDEBUG%s] %s", ColorCyan, ColorReset, msg)
	}
}

// info log
func logInfo(msg string) {
	log.Printf("[%sINFO%s] %s", ColorGreen, ColorReset, msg)
}

// warning log
func logWarning(msg string) {
	log.Printf("[%sWARNING%s] %s", ColorYellow, ColorReset, msg)
}

// error log
func logError(msg string) {
	log.Printf("[%sERROR%s] %s", ColorRed, ColorReset, msg)
}

// print timestamp
func printUpdated(t time.Time) string {
	return fmt.Sprintf("\n<i>Updated:</i> <code>%s</code>", t.Format("2006-01-02 15:04:05"))
}

// split string time to hour and minute
func splitTime(srcTime string) (int, int) {
	t, _ := time.Parse("15:04", srcTime)
	return t.Hour(), t.Minute()
}

// check if current time is in interval
func nowIsBetween(from string, to string) bool {
	t := time.Now()
	h, m := t.Hour(), t.Minute()
	h1, m1 := splitTime(from)
	h2, m2 := splitTime(to)
	if (h1 < h || h1 == h && m1 <= m) && (h < h2 || h == h2 && m < m2) {
		return true
	}
	return false
}

// calculate optimal row length for many buttons
func calcRowLength(x int) int {
	// in telegram max row length is 8
	inRow := 8
	if x > inRow && x%inRow > 0 {
		inRow = x / (x/inRow + 1)
		if x%inRow > 0 {
			inRow++
		}
	}
	return inRow
}

// MAIN FUNCTIONS

// init telegram bot
func initBot() tgbotapi.UpdatesChannel {
	var updates tgbotapi.UpdatesChannel
	var err error
	Bot, err = tgbotapi.NewBotAPI(CFG.BotToken)
	if err != nil {
		log.Panic(err)
	}
	// Bot.Debug = CFG.DebugMode
	logInfo(fmt.Sprintf("[init] Authorized on bot account %s", Bot.Self.UserName))

	whInfo, _ := Bot.GetWebhookInfo()
	logDebug(fmt.Sprintf("[init] Got webhook info: %v", whInfo.URL))
	// check webhook is set
	if CFG.UseWebhook && whInfo.URL != CFG.WebhookURL+Bot.Token {
		wh, _ := tgbotapi.NewWebhook(CFG.WebhookURL + Bot.Token)
		_, err := Bot.Request(wh)
		if err != nil {
			log.Panic(err)
		}
		logDebug(fmt.Sprintf("[init] New webhook: %s", CFG.WebhookURL+Bot.Token))
	} else if !CFG.UseWebhook && whInfo.URL != "" {
		_, err = Bot.Request(tgbotapi.DeleteWebhookConfig{})
		if err != nil {
			log.Panic(err)
		}
		logDebug("[init] Webhook deleted")
	}
	// set bot commands
	_, err = Bot.Request(tgbotapi.NewSetMyCommands(BotCommands...))
	if err != nil {
		logError(fmt.Sprintf("[init] Set commands failed: %v", err))
	}
	// init pingers
	Pingers = make(map[int64]ping.Pinger)
	// init user data
	Data = make(map[int64]*UserData)
	for uid := range Users {
		initUserData(uid)
	}
	// load user data from files
	d, err := os.Open("data")
	if err != nil && os.IsNotExist(err) {
		logWarning("[init] Creating new data directory")
		os.Mkdir("data", 0755)
		d, _ = os.Open("data")
	}
	dFiles, err := d.Readdir(0)
	if err != nil {
		logError(fmt.Sprintf("[init] Read data files failed: %v", err))
	}
	d.Close()
	for _, v := range dFiles {
		uid, _ := strconv.ParseInt(strings.TrimSuffix(v.Name(), ".gob"), 10, 64)
		logDebug(fmt.Sprintf("[init] Loading data file: %s", v.Name()))
		loadUserData(uid)
	}
	// init cron
	Cron = cron.New()
	for uid := range Users {
		// init cron only for authorized in gray database users
		if Users[uid].Token != "" {
			initUserCron(uid)
		}
	}
	Cron.Start()
	if CFG.UseWebhook {
		// serve http
		go http.ListenAndServe(":"+CFG.ListenPort, nil)
		updates = Bot.ListenForWebhook("/" + Bot.Token)
		logInfo(fmt.Sprintf("[init] Listening on port %s", CFG.ListenPort))
	} else {
		// start polling
		updateConfig := tgbotapi.NewUpdate(0)
		updateConfig.Timeout = 30
		updates = Bot.GetUpdatesChan(updateConfig)
		logInfo("[init] Start polling")
	}
	return updates
}

// init user cron
func initUserCron(uid int64) {
	if Users[uid].RefreshEnabled {
		updateCronJob(uid)
		updateCronEntry(uid, "start")
		updateCronEntry(uid, "stop")
	} else {
		for key := range Data[uid].Cron {
			removeCronEntry(uid, key)
		}
	}
}

// init empty user data
func initUserData(uid int64) {
	Data[uid] = &UserData{}
	Data[uid].Cron = map[string]cron.EntryID{"job": 0, "start": 0, "stop": 0}
}

// init configuration
func initConfig() error {
	// load main config
	err := readYML(&CFG, CFGFILE)
	if err != nil {
		return err
	}
	// init users config
	Users = make(map[int64]*UserConfig)
	c, err := os.Open("config")
	cFiles, err := c.Readdir(0)
	if err != nil {
		logError(fmt.Sprintf("[init] Read config files failed: %v", err))
	}
	c.Close()
	for _, v := range cFiles {
		uid, err := strconv.ParseInt(strings.TrimSuffix(v.Name(), ".yml"), 10, 64)
		if err == nil {
			logDebug(fmt.Sprintf("[init] Loading config file: %s", v.Name()))
			loadUserConfig(uid)
		}
	}
	// init admin account
	if !userIsAuthorized(CFG.Admin) {
		logWarning("[init] Creating admin config")
		initUserConfig(CFG.Admin, "admin")
	}
	// template functions
	funcMap := template.FuncMap{
		"fmtBytes": fmtBytes,
		"fmtKbits": func(x uint) string { return fmtBytes(x*125, true) },
		"fmtState": func(b bool) string {
			if b {
				return "enabled"
			}
			return "disabled"
		},
		"fmtPhone":   fmtPhone,
		"fmtAddress": fmtAddress,
		"inc":        func(x int) int { return x + 1 },
	}
	// load templates
	TPL, err = template.New("templates").Funcs(funcMap).ParseGlob("templates/*")
	if err != nil {
		logError(fmt.Sprintf("[template] Parse failed: %v", err))
		return err
	}
	for _, t := range TPL.Templates() {
		logDebug(fmt.Sprintf("[template] Loaded: %v", t.Name()))
	}
	return nil
}

// save main config to file
func saveConfig() error {
	return writeYML(&CFG, CFGFILE)
}

// save user config to file
func saveUserConfig(uid int64) error {
	return writeYML(Users[uid], fmt.Sprintf("config/%d.yml", uid))
}

// init new user config
func initUserConfig(uid int64, name string) error {
	if name == "" {
		name = fmt.Sprintf("user-%d", uid)
	}
	u := UserConfig{Name: name}
	logWarning(fmt.Sprintf("[config] Using default config for %d", uid))
	err := readYML(&u, "config/default.yml")
	if err != nil {
		return err
	}
	Users[uid] = &u
	return saveUserConfig(uid)
}

// load user config from file
func loadUserConfig(uid int64) error {
	var u UserConfig
	filename := fmt.Sprintf("config/%d.yml", uid)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return initUserConfig(uid, "")
	}
	err := readYML(&u, filename)
	if err != nil {
		return err
	}
	Users[uid] = &u
	return nil
}

// read config from yaml
func readYML(cfg interface{}, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		logError(fmt.Sprintf("[config] Read file failed: %v", err))
		return err
	}
	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		logError(fmt.Sprintf("[config] Parse yaml failed: %v", err))
		return err
	}
	logInfo(fmt.Sprintf("[config] Loaded %s", filename))
	return nil
}

// write config to yaml
func writeYML(cfg interface{}, filename string) error {
	// encode to yaml
	data, err := yaml.Marshal(cfg)
	if err != nil {
		logError(fmt.Sprintf("[config] YAML marshal failed: %v", err))
		return err
	}
	// attach document start and end strings
	data = append([]byte("---\n"), data...)
	data = append(data, []byte("...\n")...)
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		logError(fmt.Sprintf("[config] Write file failed: %v", err))
		return err
	}
	logInfo(fmt.Sprintf("[config] Saved %s", filename))
	return nil
}

// save user data to file (only tickets)
func saveUserData(uid int64) error {
	f, err := os.Create(fmt.Sprintf("data/%d.gob", uid))
	defer f.Close()
	if err != nil {
		logError(fmt.Sprintf("[save] Failed to open file: %v", err))
		return err
	}
	encoder := gob.NewEncoder(f)
	err = encoder.Encode(Data[uid].Tickets)
	if err != nil {
		logError(fmt.Sprintf("[save] Failed to encode data: %v", err))
		return err
	}
	return nil
}

// load user data from file (only tickets)
func loadUserData(uid int64) error {
	var d Tickets
	f, err := os.Open(fmt.Sprintf("data/%d.gob", uid))
	defer f.Close()
	if err != nil {
		logError(fmt.Sprintf("[load] Failed to open file: %v", err))
		return err
	}
	decoder := gob.NewDecoder(f)
	err = decoder.Decode(&d)
	if err != nil {
		logError(fmt.Sprintf("[load] Failed to decode data: %v", err))
		return err
	}
	Data[uid].Tickets = d
	return nil
}

// add/delete user
func manageUser(args string, enabled bool) string {
	u, name := splitArgs(args)
	uid, err := strconv.ParseInt(u, 10, 64)
	if err != nil || uid == 0 {
		return fmtErr("Wrong uid")
	}
	var msgUser, msgAdmin string
	if enabled && !userIsAuthorized(uid) {
		initUserConfig(uid, name)
		initUserData(uid)
		logInfo(fmt.Sprintf("[user] %d (%s) added", uid, Users[uid].Name))
		msgUser = "You are added to authorized users list."
		msgAdmin = fmt.Sprintf("User <code>%d</code> <b>%s</b> added.", uid, Users[uid].Name)
	} else if !enabled && userIsAuthorized(uid) {
		logInfo(fmt.Sprintf("[user] removing %d (%s)", uid, Users[uid].Name))
		msgUser = "You are removed from authorized users list."
		msgAdmin = fmt.Sprintf("User <code>%d</code> <b>%s</b> removed.", uid, Users[uid].Name)
		delete(Users, uid)
		delete(Data, uid)
		os.Remove(fmt.Sprintf("config/%d.yml", uid))
		os.Remove(fmt.Sprintf("data/%d.gob", uid))
	} else {
		return "Nothing to do"
	}
	sendTo(uid, msgUser)
	return msgAdmin
}

// send text message with keyboard (both reply or inline) to user
func sendMessage(id int64, text string, kb interface{}) (tgbotapi.Message, error) {
	if len(text) > 4096 {
		logWarning(fmt.Sprintf("Message too long: %d", len(text)))
		text = fmtErr("Message too long!")
	}
	msg := tgbotapi.NewMessage(id, text)
	msg.ParseMode = tgbotapi.ModeHTML
	msg.ReplyMarkup = kb
	res, err := Bot.Send(msg)
	if err != nil {
		logError(fmt.Sprintf("[send] [%s] %v, msg: %#v ", Users[id].Name, err, msg))
	}
	return res, err
}

// clear custom keyboard
func clearReplyKeyboard(uid int64) {
	k := tgbotapi.NewRemoveKeyboard(true)
	// send and remove dummy message
	m, _ := sendMessage(uid, "Dummy", k)
	Bot.Request(tgbotapi.NewDeleteMessage(uid, m.MessageID))
}

// edit message with inline keyboard
func editMessage(m *tgbotapi.Message, textNew string, kbNew tgbotapi.InlineKeyboardMarkup, kbReplace bool) error {
	if len(textNew) > 4096 {
		logWarning(fmt.Sprintf("Message too long: %d", len(textNew)))
		textNew = fmtErr("Message too long!")
	}
	var kb tgbotapi.InlineKeyboardMarkup
	var msg tgbotapi.Chattable
	if kbReplace {
		kb = kbNew
	} else {
		kb = *m.ReplyMarkup
	}
	if textNew == "" {
		tmp := tgbotapi.NewEditMessageReplyMarkup(m.Chat.ID, m.MessageID, kb)
		msg = &tmp
	} else {
		tmp := tgbotapi.NewEditMessageTextAndMarkup(m.Chat.ID, m.MessageID, textNew, kb)
		tmp.ParseMode = tgbotapi.ModeHTML
		msg = &tmp
	}
	_, err := Bot.Send(msg)
	if err != nil {
		logError(fmt.Sprintf("[edit] %v, msg: %#v ", err, msg))
	}
	return err
}

// generate keyboard markup from matrix
func genKeyboard(matrix [][]map[string]string) tgbotapi.InlineKeyboardMarkup {
	var kb [][]tgbotapi.InlineKeyboardButton
	for _, rows := range matrix {
		var row []tgbotapi.InlineKeyboardButton
		for _, cols := range rows {
			for key, val := range cols {
				btn := tgbotapi.NewInlineKeyboardButtonData(key, val)
				row = append(row, btn)
			}
		}
		kb = append(kb, row)
	}
	return tgbotapi.InlineKeyboardMarkup{
		InlineKeyboard: kb,
	}
}

// shortcut for keyboard with one close button
func closeButton() tgbotapi.InlineKeyboardMarkup {
	return genKeyboard([][]map[string]string{{{"close": "close"}}})
}

// generate pagination keyboard row
func rowPagination(cmd string, page int, total int) [][]map[string]string {
	// make matrix with empty row
	buttons := [][]map[string]string{{}}
	if page > 1 {
		if page > 2 {
			// first page
			buttons[0] = append(buttons[0], map[string]string{"<<": fmt.Sprintf("%s %d", cmd, 1)})
		}
		// previous page
		buttons[0] = append(buttons[0], map[string]string{"<": fmt.Sprintf("%s %d", cmd, page-1)})
	}
	if page < total {
		// next page
		buttons[0] = append(buttons[0], map[string]string{">": fmt.Sprintf("%s %d", cmd, page+1)})
		if page < total-1 {
			// last page
			buttons[0] = append(buttons[0], map[string]string{">>": fmt.Sprintf("%s %d", cmd, total)})
		}
	}
	return buttons
}

// shortcut for edit only text
func editText(m *tgbotapi.Message, txt string) error {
	empty := tgbotapi.InlineKeyboardMarkup{InlineKeyboard: [][]tgbotapi.InlineKeyboardButton{}}
	if m.ReplyMarkup != nil {
		return editMessage(m, txt, empty, false)
	}
	return editMessage(m, txt, empty, true)
}

// shortcut for edit only keyboard
func editKeyboard(m *tgbotapi.Message, kb tgbotapi.InlineKeyboardMarkup) error {
	return editMessage(m, "", kb, true)
}

// shortcut for edit text and remove inline keyboard
func editTextRemoveKeyboard(m *tgbotapi.Message, txt string) error {
	empty := tgbotapi.InlineKeyboardMarkup{InlineKeyboard: [][]tgbotapi.InlineKeyboardButton{}}
	return editMessage(m, txt, empty, true)
}

// shortcut for edit text and keyboard
func editTextAndKeyboard(m *tgbotapi.Message, txt string, kb tgbotapi.InlineKeyboardMarkup) error {
	return editMessage(m, txt, kb, true)
}

// shortcut for simple text message
func sendTo(id int64, text string) (tgbotapi.Message, error) {
	empty := tgbotapi.InlineKeyboardMarkup{InlineKeyboard: [][]tgbotapi.InlineKeyboardButton{}}
	return sendMessage(id, text, empty)
}

// shortcut for text message with close button
func sendAlert(id int64, text string) (tgbotapi.Message, error) {
	return sendMessage(id, text, closeButton())
}

// broadcast message to all users
func broadcastSend(text string) string {
	var res string
	if text == "" {
		return fmtErr("empty message")
	}
	for uid := range Users {
		_, err := sendTo(uid, text)
		if err == nil {
			res += fmt.Sprintf("%d OK\n", uid)
		} else {
			res += fmt.Sprintf("%d failed: %v\n", uid, err)
		}
	}
	return res
}

// universal api request
func requestAPI(method string, endpoint string, args map[string]interface{}) (map[string]interface{}, error) {
	logDebug(fmt.Sprintf("[API %s] endpoint: %s, args: %+v", method, endpoint, args))
	var res map[string]interface{}
	if endpoint == "" {
		return res, errors.New("Empty endpoint")
	}
	// pack arguments to body
	var reqBody *bytes.Buffer
	if len(args) > 0 {
		reqData, err := json.Marshal(args)
		if err != nil {
			logError(fmt.Sprintf("[API %s] Pack args to json failed: %v, args: %+v", method, err, args))
			return res, errors.New("Packing arguments to json failed")
		}
		reqBody = bytes.NewBuffer(reqData)
	}
	// ensure that there is no double // symbols in url
	url := strings.TrimRight(CFG.InkoToolsAPI, "/") + "/" + strings.TrimLeft(endpoint, "/")
	// make request
	var req *http.Request
	var err error
	// workaround typed and untyped nil
	if reqBody == nil {
		req, err = http.NewRequest(method, url, nil)
	} else {
		req, err = http.NewRequest(method, url, reqBody)
	}
	if err != nil {
		logError(fmt.Sprintf("[API %s] Creating request object failed: %v, url: %s", method, err, url))
		return res, errors.New("Creating request object failed")
	}
	req.Header.Add("Content-Type", "application/json")
	// send json request to api
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logError(fmt.Sprintf("[API %s] Request failed: %v, endpoint: %s", method, err, endpoint))
		return res, errors.New("API request failed")
	}
	defer resp.Body.Close()
	// parse response
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		logError(fmt.Sprintf("[API %s] Response json decode failed: %v, endpoint: %s", method, err, endpoint))
		return res, errors.New("API response decode failed")
	}
	// if we have no errors from api - return result
	if resp.StatusCode < 400 {
		logDebug(fmt.Sprintf("[API %s] Response: %+v", method, res))
		return res, nil
	}
	// parse errors from api
	if res["detail"] != nil {
		logWarning(fmt.Sprintf("[API %s] Returned %d error: %v, endpoint: %s", method, resp.StatusCode, res["detail"], endpoint))
		switch res["detail"].(type) {
		case string:
			return res, errors.New(res["detail"].(string))
		case []interface{}:
			return res, fmt.Errorf("%d", resp.StatusCode)
		}
	}
	logError(fmt.Sprintf("[API %s] Returned %d error, raw response: %#v, endpoint: %s", method, resp.StatusCode, res, endpoint))
	return res, fmt.Errorf("%d", resp.StatusCode)
}

// api get request shortcut
func apiGet(endpoint string) (map[string]interface{}, error) {
	return requestAPI("GET", endpoint, map[string]interface{}{})
}

// api delete request shortcut
func apiDelete(endpoint string) (map[string]interface{}, error) {
	return requestAPI("DELETE", endpoint, map[string]interface{}{})
}

// get switch summary and format it with template
func swSummary(ip string, style string) (string, error) {
	var res, template string
	var err error
	var sw Switch
	switch style {
	case "short":
		template = "sw.short.tmpl"
	default:
		template = "sw.tmpl"
	}
	resp, err := apiGet(fmt.Sprintf("/sw/%s/", ip))
	if err != nil {
		return fmtErr(err.Error()), err
	}
	// serialize data from returned map to struct
	mapstructure.Decode(resp["data"], &sw)
	res = fmtObj(sw, template)
	if !sw.Status {
		err = errors.New("unavailable")
	}
	return res, err
}

// get port summary and format it with template
func portSummary(ip string, port string, style string) (string, error) {
	var res string        // result string
	var pInfo PortSummary // main port summary object
	var accessPorts []int // list of access ports (for checks)
	var arpTmp []ARPEntry // for arp table deduplication

	// get slots info, return on error
	resp, err := apiGet(fmt.Sprintf("/sw/%s/ports/%s/", ip, port))
	if err != nil {
		return res, err
	}
	mapstructure.Decode(resp["data"], &pInfo.Slots)

	// set common port values
	pInfo.PortNumber = pInfo.Slots[0].Port
	pInfo.Style = style
	for p := range pInfo.Slots {
		if pInfo.Slots[p].Link {
			pInfo.LinkUp = true
			break
		}
	}

	// get port counters
	resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/counters", ip, port))
	if err != nil {
		pInfo.Counters.Error = err.Error()
	} else {
		mapstructure.Decode(resp["data"], &pInfo.Counters)
	}

	// all other data for full style
	if style == "full" {

		// get port bandwidth
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/bandwidth", ip, port))
		if err == nil {
			mapstructure.Decode(resp["data"], &pInfo.Bandwidth)
		}

		// get list of access ports
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/", ip))
		if err == nil {
			mapstructure.Decode(resp["data"].(map[string]interface{})["access_ports"], &accessPorts)
		}

		// get vlan
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/vlan", ip, port))
		if err != nil {
			pInfo.VLAN.Error = err.Error()
		} else {
			mapstructure.Decode(resp["data"], &pInfo.VLAN)
		}

		// all other data only for access ports
		if !intInList(pInfo.PortNumber, accessPorts) {
			e := "Transit ports are not supported"
			pInfo.ACL.Error = e
			pInfo.Multicast.Error = e
			pInfo.MAC.Error = e
			pInfo.ARP.Error = e
		} else {

			// get acl
			resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/acl", ip, port))
			if err != nil {
				pInfo.ACL.Error = err.Error()
			} else {
				mapstructure.Decode(resp["data"], &pInfo.ACL.Entries)
			}

			// get multicast data
			resp, err = apiGet(fmt.Sprintf("/sw/%s/multicast", ip))
			if err != nil {
				pInfo.Multicast.Error = err.Error()
			} else {
				mapstructure.Decode(resp["data"], &pInfo.Multicast)
				// check if port is member of mvlan
				pInfo.Multicast.State = intInList(pInfo.PortNumber, pInfo.Multicast.MemberPorts)
				if pInfo.Multicast.State {
					// mcast filters
					resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/mcast/filters", ip, port))
					if err == nil {
						mapstructure.Decode(resp["data"], &pInfo.Multicast.Filters)
					}
					if pInfo.LinkUp {
						// mcast groups
						resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/mcast/groups", ip, port))
						if err == nil {
							mapstructure.Decode(resp["data"], &pInfo.Multicast.Groups)
						}
					}
				}
			}

			// get mac table only if link is up
			if pInfo.LinkUp {
				resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/mac", ip, port))
				if err != nil {
					pInfo.MAC.Error = err.Error()
				} else {
					mapstructure.Decode(resp["data"], &pInfo.MAC.Entries)
				}
			}

			// get arp only if mac address table is not empty
			if len(pInfo.MAC.Entries) > 0 {
				// get arp table for acl permit ip
				for _, a := range pInfo.ACL.Entries {
					if a.Mode == "permit" {
						resp, err = requestAPI("POST", "/arpsearch", map[string]interface{}{"ip": a.IP})
						if err != nil {
							logWarning(fmt.Sprintf("[ARP] failed to get %s", a.IP))
							pInfo.ARP.Error += err.Error() + "\n"
						} else {
							mapstructure.Decode(resp["data"], &arpTmp)
							// append to global arp
							pInfo.ARP.Entries = append(pInfo.ARP.Entries, arpTmp...)
						}
					}
				}
				// get arp for each mac address
				for _, m := range pInfo.MAC.Entries {
					resp, err = requestAPI("POST", "/arpsearch", map[string]interface{}{"mac": m.Mac, "src_sw_ip": ip})
					if err != nil {
						logWarning(fmt.Sprintf("[ARP] failed to get %s", m.Mac))
						pInfo.ARP.Error += err.Error() + "\n"
					} else {
						mapstructure.Decode(resp["data"], &arpTmp)
						// append to global arp
						pInfo.ARP.Entries = append(pInfo.ARP.Entries, arpTmp...)
					}
				}
				// remove duplicate entries from global arp table
				arpTmp = pInfo.ARP.Entries
				pInfo.ARP.Entries = nil
				for _, a := range arpTmp {
					dup := false
					for _, u := range pInfo.ARP.Entries {
						if u == a {
							dup = true
							break
						}
					}
					if !dup {
						pInfo.ARP.Entries = append(pInfo.ARP.Entries, a)
					}
				}
			} // end arp

		} // end access ports

	} // end full style

	logDebug(fmt.Sprintf("[portSummary] pInfo: %+v", pInfo))
	res = fmtObj(pInfo, "port.tmpl")
	res += printUpdated(time.Now())
	// clear previous errors (escalated to template)
	err = nil
	return res, err
}

// clear port counters
func portClear(ip string, port string) string {
	resp, err := apiDelete(fmt.Sprintf("/sw/%s/ports/%s/counters", ip, port))
	if err != nil {
		return fmtErr(err.Error())
	}
	if resp["detail"] == nil {
		logError(fmt.Sprintf("[clear %s %s] API returned no detail, raw data: %v", ip, port, resp))
		return fmtErr("Empty response")
	}
	return resp["detail"].(string)
}

// get ip summary
func ipCalc(ip string) string {
	var res string
	resp, err := apiGet(fmt.Sprintf("/ipcalc/%s/", ip))
	if err != nil {
		return fmtErr(err.Error())
	}
	var calc IPCalc
	mapstructure.Decode(resp["data"], &calc)
	res += fmtObj(calc, "ipcalc.tmpl")
	return res
}

// TELEGRAM COMMANDS HANDLERS

// new user handler
func newUserHandler(u *tgbotapi.User) {
	msg := fmt.Sprintf("User <a href=\"tg://user?id=%d\">%s</a> "+
		" requests authorization:\nid: <code>%d</code>", u.ID, u, u.ID)
	sendTo(CFG.Admin, msg)
	sendTo(u.ID, "Your request is accepted. Waiting confirmation from admin.")
}

// admin command handler
func adminHandler(msg string) string {
	cmd, arg := splitArgs(msg)
	var res string
	var err error
	switch cmd {
	case "list":
		for id, u := range Users {
			res += fmt.Sprintf(
				"<code>%d</code> - <a href=\"tg://user?id=%d\">%s</a>\n", id, id, u.Name)
		}
	case "add":
		res = manageUser(arg, true)
	case "del":
		res = manageUser(arg, false)
	case "send":
		user, text := splitArgs(arg)
		id, _ := strconv.ParseInt(user, 10, 64)
		_, err = sendTo(id, text)
		if err == nil {
			res = "Message sent"
		} else {
			res = fmt.Sprintf("Message not sent: %v", err)
		}
	case "broadcast":
		res = broadcastSend(arg)
	case "reload":
		err = initConfig()
		if err != nil {
			res = "Failed"
		} else {
			res = "Config reloaded"
		}
	default:
		res = HELPADMIN
	}
	return res
}

// parse raw input handler
func rawHandler(raw string) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string                       // text message result
	var kb tgbotapi.InlineKeyboardMarkup // inline keyboard markup
	cmd, args := splitArgs(raw)
	ip := fullIP(cmd, false)
	switch {
	// empty input
	case raw == "":
		// skip
	// cmd is ip address
	case ip != "":
		// ip is sw ip
		if fullIP(ip, true) != "" {
			port, args := splitArgs(args)
			res, kb = swHandler(ip, port, args)
			// ip is client ip
		} else {
			res, kb = clientHandler(ip, args)
		}
	// cmd is contract id
	case isContract(cmd):
		res, kb = clientHandler(cmd, args)
	default:
		// search in db by default
		res, kb = searchHandler(raw, 1)
	}
	// default keyboard with close button
	if len(kb.InlineKeyboard) == 0 {
		kb = closeButton()
	}
	return res, kb
}

// switch ip handler
func swHandler(ip string, port string, args string) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string // text message result
	var err error
	var kb tgbotapi.InlineKeyboardMarkup // inline keyboard markup
	pView := []string{"short", "full"}   // view styles for port summary
	idx := 0                             // default index - short view
	logDebug(fmt.Sprintf("[swHandler] ip: %s, port: %s, args: '%s'", ip, port, args))
	// empty or invalid port - return full sw info
	if _, err := strconv.Atoi(port); err != nil {
		res, err = swSummary(ip, "full")
		if err == nil || err.Error() == "unavailable" {
			kb = genKeyboard([][]map[string]string{{
				{"refresh": fmt.Sprintf("raw edit %s", ip)},
				{"close": "close"},
			}})
		}
		return res, kb
	}
	// clear counters if needed
	if strings.Contains(args, "clear") {
		logDebug(fmt.Sprintf("[swHandler] Clear result: %s", portClear(ip, port)))
	}
	if strings.Contains(args, "full") {
		idx = 1
	}
	// for ports switch view is always short
	res, err = swSummary(ip, "short")
	// no need to check port if switch is unavailable
	if err != nil {
		return res, kb
	}
	// get port summary
	p, err := portSummary(ip, port, pView[idx])
	if err != nil {
		return fmtErr(err.Error()), kb
	}
	res += p
	kb = genKeyboard([][]map[string]string{
		{
			// inverted view for full/short button calculated as (1 - idx)
			{pView[1-idx]: fmt.Sprintf("raw edit %s %s %s", ip, port, pView[1-idx])},
			{"clear counters": fmt.Sprintf("raw edit %s %s %s clear", ip, port, pView[idx])},
		},
		{
			{"refresh": fmt.Sprintf("raw edit %s %s %s", ip, port, pView[idx])},
			{"repeat": fmt.Sprintf("raw send %s %s %s", ip, port, pView[idx])},
			{"close": "close"},
		},
	})
	return res, kb
}

// ip calc handler
func calcHandler(arg string) string {
	var res string
	ip := fullIP(arg, false)
	if ip == "" {
		res = fmt.Sprintf("[calc] wrong ip: %s", arg)
	} else {
		res = ipCalc(ip)
	}
	return res
}

// client ip / contract id handler
func clientHandler(client string, args string) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string                       // text message result
	var kb tgbotapi.InlineKeyboardMarkup // inline keyboard markup
	var btns []string                    // switch view buttons text
	var cData Contract                   // client data struct
	var endpoint, template, style string
	logDebug(fmt.Sprintf("[clientHandler] client: %s, args: %s", client, args))
	view, args := splitArgs(args)
	// set api request style, view template and buttons
	switch view {
	case "billing":
		style = "billing"
		template = "contract.billing.tmpl"
		btns = []string{"contacts", "tickets"}
	case "tickets":
		style = "short"
		template = "contract.tickets.tmpl"
		btns = []string{"contacts", "billing"}
	default:
		style = "short"
		template = "contract.short.tmpl"
		btns = []string{"tickets", "billing"}
	}
	// client is contract id or ip address
	if isContract(client) {
		endpoint = fmt.Sprintf("/gdb/%s/?style=%s", client, style)
	} else {
		endpoint = fmt.Sprintf("/gdb/by-ip/%s/?style=%s", client, style)
	}
	resp, err := apiGet(endpoint)
	if err != nil {
		res = fmtErr(err.Error())
	} else {
		if style == "billing" {
			mapstructureDecode(resp["data"], &cData.Billing)
			mapstructureDecode(resp["meta"], &cData) // contract id
		} else {
			mapstructureDecode(resp["data"], &cData)
		}
		res = fmtObj(cData, template)
		gdbURL := strings.TrimRight(CFG.GraydbURL, "/") + fmt.Sprintf("/index.php?id_aabon=%d", cData.ClientID)
		gdbArchiveURL := strings.TrimRight(CFG.GraydbURL, "/") + fmt.Sprintf("/arx_zay.php?dogovor=%s", cData.ContractID)
		// init keyboard with empty row
		kb = tgbotapi.NewInlineKeyboardMarkup(tgbotapi.NewInlineKeyboardRow())
		// add view buttons to row
		for _, btn := range btns {
			// skip tickets button if no tickets
			if btn == "tickets" && len(cData.Tickets) == 0 {
				continue
			}
			kb.InlineKeyboard[0] = append(
				kb.InlineKeyboard[0],
				tgbotapi.NewInlineKeyboardButtonData(btn, fmt.Sprintf("raw edit %s %s", client, btn)),
			)
		}
		// add tickets commenting buttons
		if view == "tickets" {
			for i, ticket := range cData.Tickets {
				kb.InlineKeyboard = append(kb.InlineKeyboard,
					tgbotapi.NewInlineKeyboardRow(
						tgbotapi.NewInlineKeyboardButtonData(
							fmt.Sprintf(" add comment [%d] (%s)", i+1, ticket.Master),
							fmt.Sprintf("comment edit %s %d", cData.ContractID, ticket.TicketID),
						),
					),
				)
			}
		}
		// add other rows
		kb.InlineKeyboard = append(kb.InlineKeyboard,
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonURL("open in gray database", gdbURL),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonURL("tickets archive", gdbArchiveURL),
			),
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("close", "close"),
			),
		)
		// check client switch ip and port and add port button
		ip := fullIP(cData.SwitchIP, true)
		port, err := strconv.Atoi(cData.Port)
		if ip != "" && err == nil {
			kb.InlineKeyboard[0] = append(
				kb.InlineKeyboard[0],
				tgbotapi.NewInlineKeyboardButtonData(
					"port info", fmt.Sprintf("raw send %s %d", ip, port)))
		}
	}
	return res, kb
}

// search mode handler
func searchHandler(kw string, page int) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string                       // text message result
	var kb tgbotapi.InlineKeyboardMarkup // inline keyboard markup
	resp, err := requestAPI("POST", "/db/search", map[string]interface{}{"keyword": kw, "page": page, "per_page": 4})
	if err != nil {
		res = fmt.Sprintf("Search for '%s': %v", kw, err)
	} else {
		var result DBSearch
		err = mapstructure.Decode(resp, &result)
		if err != nil {
			logError(fmt.Sprintf("[search] %v", err))
		} else {
			res = fmtObj(result, "search.tmpl")
			// callback pagination
			if result.Meta.Pages.Total > 1 {
				kb = genKeyboard(append(
					rowPagination(fmt.Sprintf("search edit %s", kw), page, result.Meta.Pages.Total),
					[]map[string]string{{"close": "close"}}))
			}
		}
	}
	return res, kb
}

// start user pinger
func pingerStart(uid int64, host string) error {
	// one user can ping one host at time
	if _, exist := Pingers[uid]; exist {
		pingerStop(uid)
	}
	logDebug(fmt.Sprintf("[ping] [%s] starting %s", Users[uid].Name, host))
	p, err := ping.NewPinger(host)
	if err != nil {
		logError(fmt.Sprintf("[ping] [%s] [%s] %v", Users[uid].Name, host, err))
		return err
	}
	// start message
	p.OnSetup = func() {
		// add static keyboard with stop button
		kb := tgbotapi.NewReplyKeyboard(tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton("stop")))
		res := fmt.Sprintf("<pre>PING %s (%v) %d (%d) bytes of data.</pre>",
			p.Addr(), p.IPAddr(), p.Size, p.Size+28)
		sendMessage(uid, res, kb)
	}
	// send ping result for each packet
	p.OnRecv = func(pkt *ping.Packet) {
		sendTo(uid, fmt.Sprintf("<pre>%d bytes from %v: icmp_seq=%d time=%v</pre>",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, fmtRTT(pkt.Rtt)))
	}
	p.OnDuplicateRecv = func(pkt *ping.Packet) {
		sendTo(uid, fmt.Sprintf("<pre>%d bytes from %v: icmp_seq=%d time=%v (DUP!)</pre>",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, fmtRTT(pkt.Rtt)))
	}
	// send total statistics when stopped
	p.OnFinish = func(stats *ping.Statistics) {
		res := fmt.Sprintf("<pre>%s (%s) stats:\n"+
			"%d sent, %d received, %v%% loss\n"+
			"rtt min/avg/max/stddev:\n%v/%v/%v/%v</pre>",
			stats.Addr, stats.IPAddr,
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss,
			fmtRTT(stats.MinRtt), fmtRTT(stats.AvgRtt), fmtRTT(stats.MaxRtt), fmtRTT(stats.StdDevRtt))
		// remove keyboard only if no new pinger is running
		if _, exist := Pingers[uid]; exist {
			sendTo(uid, res)
		} else {
			kb := tgbotapi.NewRemoveKeyboard(true)
			sendMessage(uid, res, kb)
		}
	}
	// add pinger to global list
	Pingers[uid] = *p
	// run ping in goroutine
	go p.Run()
	return err
}

// stop user pinger
func pingerStop(uid int64) {
	// check if pinger exists and stop it
	if _, exist := Pingers[uid]; exist {
		p := Pingers[uid]
		logDebug(fmt.Sprintf("[ping] [%s] stopping %s", Users[uid].Name, p.Addr()))
		p.Stop()
		// remove pinger from global list
		delete(Pingers, uid)
		// restore mode
		Data[uid].Mode = "raw"
	}
}

// ping mode handler
func pingHandler(msg string, uid int64) string {
	var res string // text message result
	if msg == "stop" {
		pingerStop(uid)
	} else {
		if fullIP(msg, true) != "" {
			Data[uid].Mode = "raw"
			return fmtErr("Impossible to ping switch ip without violating network conception. Use raw mode for availability checks.")
		} else if ip := fullIP(msg, false); ip != "" {
			msg = ip
		}
		if err := pingerStart(uid, msg); err != nil {
			res = fmtErr(err.Error())
			Data[uid].Mode = "raw"
		}
	}
	return res
}

// config mode handler
func configHandler(msg string, uid int64, msgID int) (string, tgbotapi.InlineKeyboardMarkup) {
	// msgID is for deferred message deletion
	var res string
	var kb tgbotapi.InlineKeyboardMarkup

	// subcommands processing, msg - subcommand
	if Data[uid].TMP == "" {
		switch msg {
		case "login", "interval", "from", "to":
			res = fmt.Sprintf("Enter new '%s' value:", msg)
			// change mode for user input and save tmp data
			Data[uid].Mode = "config"
			Data[uid].TMP = fmt.Sprintf("%d %s", msgID, msg)
		case "toggleRefresh":
			Users[uid].RefreshEnabled = !Users[uid].RefreshEnabled
			initUserCron(uid)
		case "toggleNew":
			Users[uid].NotifyNew = !Users[uid].NotifyNew
		case "toggleUpdate":
			Users[uid].NotifyUpdate = !Users[uid].NotifyUpdate
		}

	} else { // input mode, msg - data entered by user
		// unpack saved data
		strID, savedData := splitArgs(Data[uid].TMP)
		enteredKey, savedData := splitArgs(savedData)
		oldMsgID, _ := strconv.Atoi(strID)
		enteredValue := msg
		// delete previous bot message
		Bot.Request(tgbotapi.NewDeleteMessage(uid, oldMsgID))
		switch enteredKey {
		case "login":
			// save entered login to tmp and ask for password
			res = "Enter password:"
			Data[uid].TMP = fmt.Sprintf("%d password %s", msgID, enteredValue)
		case "password":
			// try to get gray database token from api
			resp, err := requestAPI("POST", "/gdb/user/get_token",
				map[string]interface{}{"login": savedData, "password": enteredValue})
			if err != nil {
				res = fmtErr(err.Error())
				kb = genKeyboard([][]map[string]string{{{"try again": "config edit login"}, {"close": "close"}}})
			} else {
				mapstructure.Decode(resp["data"].(map[string]interface{})["token"], &Users[uid].Token)
				// get username from api
				resp, err := requestAPI("GET", "/gdb/user", map[string]interface{}{"token": Users[uid].Token})
				if err != nil {
					Users[uid].Username = err.Error()
				} else {
					mapstructure.Decode(resp["data"].(map[string]interface{})["username"], &Users[uid].Username)
				}
			}
			Data[uid].TMP = ""
		case "interval":
			if dt, err := time.ParseDuration(enteredValue); err != nil {
				sendAlert(uid, "Invalid duration format")
			} else if dt < time.Minute {
				sendAlert(uid, "Duration is less than 1m")
			} else {
				Users[uid].RefreshInterval = enteredValue
				updateCronJob(uid)
			}
			Data[uid].TMP = ""
		case "from", "to":
			if _, err := time.Parse("15:04", enteredValue); err != nil {
				sendAlert(uid, "Invalid time format, use <code>HH:MM</code>")
			} else {
				if enteredKey == "from" {
					Users[uid].RefreshStart = enteredValue
					updateCronEntry(uid, "start")
				} else {
					Users[uid].RefreshStop = enteredValue
					updateCronEntry(uid, "stop")
				}
				// update job because working time could be changed
				updateCronJob(uid)
			}
			Data[uid].TMP = ""
		}
	}

	// restore mode on cleared tmp
	if Data[uid].TMP == "" {
		Data[uid].Mode = "raw"
		// save message on changes
		if msg != "" {
			saveUserConfig(uid)
		}
	}
	// print config on empty res
	if res == "" {
		res, kb = printConfig(uid)
	}

	return res, kb
}

// print unauthorized message
func printLogin() (string, tgbotapi.InlineKeyboardMarkup) {
	res := "You are not authorized in gray database."
	kb := genKeyboard([][]map[string]string{{{"login": "config edit login"}}})
	return res, kb
}

// print user config
func printConfig(uid int64) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string
	var kb tgbotapi.InlineKeyboardMarkup
	if Users[uid].Token == "" {
		return printLogin()
	}
	res = fmtObj(Users[uid], "config.tmpl")
	buttons := [][]map[string]string{{{"edit credentials": "config edit login"}}}
	if Users[uid].RefreshEnabled {
		buttons = append(buttons,
			[]map[string]string{
				{"disable refresh": "config edit toggleRefresh"},
				{"edit interval": "config edit interval"},
			},
			[]map[string]string{
				{"edit from": "config edit from"},
				{"edit to": "config edit to"},
			}, []map[string]string{
				{"toggle New": "config edit toggleNew"},
				{"toggle Update": "config edit toggleUpdate"},
			},
		)
	} else {
		buttons = append(buttons, []map[string]string{{"enable refresh": "config edit toggleRefresh"}})
	}
	buttons = append(buttons, []map[string]string{{"close": "close"}})
	kb = genKeyboard(buttons)
	return res, kb
}

// update cron entry
func updateCronEntry(uid int64, key string) {
	var s string
	var f func()
	// remove old entry
	removeCronEntry(uid, key)
	switch key {
	case "job":
		// set random interval +/- 15s from original
		t, _ := time.ParseDuration(Users[uid].RefreshInterval)
		t += time.Duration(rand.Intn(30)-15) * time.Second
		s = fmt.Sprintf("@every %s", t)
		f = func() { updateTickets(uid) }
	case "start":
		h, m := splitTime(Users[uid].RefreshStart)
		s = fmt.Sprintf("%d %d * * *", m, h)
		f = func() { updateCronJob(uid) }
	case "stop":
		h, m := splitTime(Users[uid].RefreshStop)
		s = fmt.Sprintf("%d %d * * *", m, h)
		f = func() { removeCronEntry(uid, "job") }
	}
	id, err := Cron.AddFunc(s, f)
	if err != nil {
		logError(fmt.Sprintf("[cron] [%s] failed to add %s entry: %v", Users[uid].Name, key, err))
	} else {
		Data[uid].Cron[key] = id
		logInfo(fmt.Sprintf("[cron] [%s] added %s entry %s [%d]", Users[uid].Name, key, s, id))
	}
}

// remove cron entry
func removeCronEntry(uid int64, key string) {
	id := Data[uid].Cron[key]
	if Cron.Entry(id).Valid() {
		Cron.Remove(id)
		logInfo(fmt.Sprintf("[cron] [%s] removed %s entry [%d]", Users[uid].Name, key, id))
	}
}

// update user job
func updateCronJob(uid int64) {
	if nowIsBetween(Users[uid].RefreshStart, Users[uid].RefreshStop) {
		updateCronEntry(uid, "job")
		// run job immediately after adding
		go Cron.Entry(Data[uid].Cron["job"]).Job.Run()
	} else {
		logWarning(fmt.Sprintf("[cron] [%s] job skipped due to working time range", Users[uid].Name))
		// remove old job
		removeCronEntry(uid, "job")
	}
}

// update user tickets cache
func updateTickets(uid int64) error {
	resp, err := requestAPI("GET", "/gdb/user/tickets", map[string]interface{}{"token": Users[uid].Token})
	if err != nil {
		return err
	}
	// save old tickets to compare with updated
	oldTickets := make(map[int][]TicketComment)
	// save old tags to restore after update
	oldTags := make(map[int]string)
	for _, e := range Data[uid].Tickets.Data {
		oldTickets[e.TicketID] = e.Comments
		oldTags[e.TicketID] = e.Tag
	}
	// clear cache before update
	Data[uid].Tickets.Data = nil
	mapstructureDecode(resp, &Data[uid].Tickets)
	// scan changes
	for i, e := range Data[uid].Tickets.Data {
		isModified := false
		if _, ok := oldTickets[e.TicketID]; !ok {
			// new ticket notification
			isModified = true
			logInfo(fmt.Sprintf("[tickets] [%s] New ticket: %s/%d", Users[uid].Name, e.ContractID, e.TicketID))
			if Users[uid].NotifyNew {
				res := fmtObj(e, "ticket.user.tmpl")
				kb := genKeyboard([][]map[string]string{{
					{"comment": fmt.Sprintf("comment edit %s %d", e.ContractID, e.TicketID)},
					{"tag": fmt.Sprintf("tag edit %d", e.TicketID)},
					{"close": "close"},
				}})
				sendMessage(uid, res, kb)
			}
		} else {
			// for old tickets copy saved user data to updated ticket
			Data[uid].Tickets.Data[i].Tag = oldTags[e.TicketID]
		}
		c := len(e.Comments)
		if c > 0 {
			// check comments
			lastComment := e.Comments[c-1]
			if lastComment.Author != Data[uid].Tickets.Meta.User {
				if c > len(oldTickets[e.TicketID]) && !isModified {
					// new comment notification (only for old tickets)
					logInfo(fmt.Sprintf("[tickets] [%s] %s commented %s/%d: %s",
						Users[uid].Name, lastComment.Author, e.ContractID, e.TicketID, lastComment.Comment))
					if Users[uid].NotifyUpdate {
						res := fmt.Sprintf("/%s %s\n%s: %s",
							e.ContractID, fmtAddress(e.Address), lastComment.Author, lastComment.Comment)
						kb := genKeyboard([][]map[string]string{{
							{"comment": fmt.Sprintf("comment edit %s %d", e.ContractID, e.TicketID)},
							{"tag": fmt.Sprintf("tag edit %d", e.TicketID)},
							{"close": "close"},
						}})
						sendMessage(uid, res, kb)
					}
				}
				isModified = true
			}
		}
		Data[uid].Tickets.Data[i].Modified = isModified
	}
	Data[uid].Tickets.Updated = time.Now()
	// save data to file
	saveUserData(uid)
	return nil
}

// get list of gray database tickets
func ticketsHandler(cmd string, uid int64) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string
	var kb tgbotapi.InlineKeyboardMarkup
	var page int
	var buttons [][]map[string]string
	if Users[uid].Token == "" {
		return printLogin()
	}
	// update tickets cache on refresh and first run
	if strings.Contains(cmd, "refresh") || Data[uid].Tickets.Updated.IsZero() {
		// trim cmd to prevent duplication in refresh button
		re, _ := regexp.Compile(`refresh ?`)
		cmd = re.ReplaceAllString(cmd, "")
		if err := updateTickets(uid); err != nil {
			return fmtErr(err.Error()), kb
		}
	}
	tickets := Data[uid].Tickets.Data
	total := len(tickets)
	if total == 0 {
		res = "You have no tickets"
	} else {
		if strings.Contains(cmd, "details") {
			_, p := splitLast(cmd)
			page, _ = strconv.Atoi(p)
			// replace invalid page numbers by first or last page
			if page < 1 {
				page = 1
			}
			if page > total {
				page = total
			}
			// get current ticket
			ticket := tickets[page-1]
			res = fmtObj(ticket, "ticket.user.tmpl")
			res += fmt.Sprintf("\nTicket: <b>%d/%d</b>", page, total)
			// pagination row
			if total > 1 {
				buttons = append(buttons, rowPagination("tickets edit details", page, total)...)
			}
			// other buttons rows
			buttons = append(buttons, []map[string]string{
				{"all tickets": "tickets edit list"},
				{"client info": fmt.Sprintf("raw send %s", ticket.ContractID)},
				{"comment": fmt.Sprintf("comment edit %s %d", ticket.ContractID, ticket.TicketID)},
				{"tag": fmt.Sprintf("tag edit %d", ticket.TicketID)},
			})
		} else {
			res = fmtObj(tickets, "ticket.list.tmpl")
			// generate index buttons
			var row []map[string]string
			inRow := calcRowLength(total)
			for i := 1; i <= total; i++ {
				row = append(row, map[string]string{strconv.Itoa(i): fmt.Sprintf("tickets edit details %d", i)})
				// next row on hit inRow count
				if len(row) == inRow {
					buttons = append(buttons, row)
					row = nil
				}
			}
			// add last row (< inRow buttons)
			if len(row) > 0 {
				buttons = append(buttons, row)
			}
		}
	}
	// common row with refresh and close buttons
	buttons = append(buttons, []map[string]string{
		{"refresh": fmt.Sprintf("tickets edit refresh %s", cmd)},
		{"close": "close"},
	})
	res += printUpdated(Data[uid].Tickets.Updated)
	kb = genKeyboard(buttons)
	return res, kb
}

// add comment to ticket
func addComment(uid int64, contract string, ticket string, comment string) {
	_, err := requestAPI("POST",
		fmt.Sprintf("/gdb/%s/tickets/%s", contract, ticket),
		map[string]interface{}{
			"token":   Users[uid].Token,
			"comment": comment,
		})
	if err != nil {
		sendAlert(uid, fmtErr(err.Error()))
	} else {
		go updateTickets(uid)
	}
}

// add comment handler
func commentHandler(args string, uid int64, msgID int) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string
	var kb tgbotapi.InlineKeyboardMarkup
	// args format for init message: 'clientID ticketID'
	reInit, _ := regexp.Compile(`^[0-9]{5} \d+$`)
	if reInit.MatchString(args) {
		// send prompt with cancel button ans save its id
		k := tgbotapi.NewReplyKeyboard(tgbotapi.NewKeyboardButtonRow(tgbotapi.NewKeyboardButton("cancel")))
		m, _ := sendMessage(uid, "Enter new comment:", k)
		// store temporary data and change mode
		Data[uid].TMP = fmt.Sprintf("%d %d %s", msgID, m.MessageID, args)
		Data[uid].Mode = "comment"
	} else if Data[uid].TMP != "" {
		// unpack temporary data [initMsgID, promtMsgID, clientID, ticketID]
		tmpData := strings.Split(Data[uid].TMP, " ")
		// delete previous two messages (init and prompt)
		for i := 0; i <= 1; i++ {
			m, _ := strconv.Atoi(tmpData[i])
			Bot.Request(tgbotapi.NewDeleteMessage(uid, m))
		}
		if args != "cancel" {
			// add new comment
			go addComment(uid, tmpData[2], tmpData[3], args)
		}
		// clear tmp, restore mode, remove cancel button, return to tickets list
		Data[uid].TMP = ""
		Data[uid].Mode = "raw"
		clearReplyKeyboard(uid)
		res, kb = ticketsHandler("list", uid)
	} else {
		res, kb = fmtErr("Wrong comment params"), closeButton()
		logError(fmt.Sprintf("[comment] Wrong params: %s", args))
	}
	return res, kb
}

// ticket tag handler
func tagHandler(args string, uid int64) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string
	var kb tgbotapi.InlineKeyboardMarkup
	var found bool
	ticket, tag := splitArgs(args)
	ticketID, _ := strconv.Atoi(ticket)
	if tag == "" {
		// no params - return keyboard with tags
		kb = genKeyboard(genTagsButtons(ticketID))
	} else {
		if tag == "clear" {
			tag = ""
		}
		// try to find ticket id in user tickets
		for i, e := range Data[uid].Tickets.Data {
			if e.TicketID == ticketID {
				Data[uid].Tickets.Data[i].Tag = tag
				saveUserData(uid)
				res = "Add comment?"
				kb = genKeyboard([][]map[string]string{{
					{"yes": fmt.Sprintf("comment edit %s %d", e.ContractID, e.TicketID)},
					{"no": "tickets edit list"},
				}})
				found = true
				break
			}
		}
		if !found {
			logError(fmt.Sprintf("[tag] ticket not found: %d", ticketID))
		}
	}
	return res, kb
}

// generate tags buttons
func genTagsButtons(ticketID int) [][]map[string]string {
	var buttons [][]map[string]string
	var row []map[string]string
	// first button - 'clear'
	row = append(row, map[string]string{" ": fmt.Sprintf("tag edit %d clear", ticketID)})
	tags := strings.Split(UserTags, ":")
	// increase count of tags because of first 'empty' tag (clear)
	inRow := calcRowLength(len(tags) + 1)
	for _, tag := range tags {
		row = append(row, map[string]string{tag: fmt.Sprintf("tag edit %d %s", ticketID, tag)})
		if len(row) == inRow {
			buttons = append(buttons, row)
			row = nil
		}
	}
	// add last row (< inRow buttons)
	if len(row) > 0 {
		buttons = append(buttons, row)
	}
	return buttons
}

// MAIN APP
func main() {
	initConfig()
	// serve telegram updates
	for u := range initBot() {
		// empty updates if user blocked or restarted bot
		if u.FromChat() == nil {
			logWarning("Empty update")
			continue
		}
		uid := u.FromChat().ID
		// for unauthorized users only start cmd is available
		if !userIsAuthorized(uid) && uid != CFG.Admin {
			if u.Message != nil && u.Message.Command() == "start" {
				newUserHandler(u.SentFrom())
			}
			// skip any other updates from unauthorized users
			continue
		}
		// message updates
		if u.Message != nil {
			logInfo(fmt.Sprintf("[message] [%s] %s", Users[uid].Name, u.Message.Text))
			var msg string                       // input message
			var res string                       // output message
			var kb tgbotapi.InlineKeyboardMarkup // output keyboard markup

			// send dummy message (will be edited after processing)
			tmpMsg, _ := sendTo(uid, "Waiting...")

			cmd := u.Message.Command()
			cmdArgs := u.Message.CommandArguments()
			if cmd != "" {
				msg = cmdArgs
			} else {
				msg = u.Message.Text
			}

			// workaround for contracts in cmd
			if isContract(cmd) {
				msg = cmd
				cmd = "raw"
			}

			// cmd processing
			switch cmd {
			case "help":
				res, kb = HELPUSER, closeButton()
				goto SEND
			case "admin":
				if uid == CFG.Admin {
					Data[uid].Mode = "admin"
				} else {
					res, kb = "You have no permissions to work in this mode", closeButton()
					goto SEND
				}
			case "raw", "comment", "config":
				Data[uid].Mode = cmd
			case "tickets":
				res, kb = ticketsHandler(msg, uid)
				goto SEND
			case "calc":
				if msg != "" {
					res, kb = calcHandler(msg), closeButton()
				}
				goto SEND
			case "ping":
				if msg != "" {
					Data[uid].Mode = cmd
				}
			// no command
			case "":
				// skip
			// wrong command
			default:
				// ignore
				goto SEND
			}

			// mode processing
			switch Data[uid].Mode {
			case "admin":
				res = adminHandler(msg)
			case "ping":
				res = pingHandler(msg, uid)
			case "config":
				// increased msgID - future answer from bot
				res, kb = configHandler(msg, uid, u.Message.MessageID+1)
			case "comment":
				res, kb = commentHandler(msg, uid, 0)
			default: // default is raw mode
				res, kb = rawHandler(msg)
			}
		SEND:
			// edit dummy message with actual res
			if res != "" {
				if len(kb.InlineKeyboard) > 0 {
					editTextAndKeyboard(&tmpMsg, res, kb)
				} else {
					editTextRemoveKeyboard(&tmpMsg, res)
				}
			} else {
				// delete dummy message on empty res
				Bot.Request(tgbotapi.NewDeleteMessage(uid, tmpMsg.MessageID))
			}
			// clear user input
			if cmd != "start" {
				Bot.Request(tgbotapi.NewDeleteMessage(uid, u.Message.MessageID))
			}

		} else if u.CallbackData() != "" { // callback updates
			logInfo(fmt.Sprintf("[callback] [%s] %s", Users[uid].Name, u.CallbackData()))
			// skip dummy button
			if u.CallbackData() == "dummy" {
				continue
			}
			msg := u.CallbackQuery.Message
			var res string                       // output message
			var kb tgbotapi.InlineKeyboardMarkup // output keyboard markup
			mode, args := splitArgs(u.CallbackData())
			action, rawCmd := splitArgs(args)

			// send dummy message or edit existing
			switch action {
			case "send":
				tmpMsg, _ := sendTo(uid, "Waiting...")
				// update pointer for message to edit after getting result
				msg = &tmpMsg
			case "edit":
				// hide existing keyboard while waiting
				editKeyboard(msg, genKeyboard([][]map[string]string{{{"Waiting...": "dummy"}}}))
			}

			switch mode {
			case "raw":
				res, kb = rawHandler(rawCmd)
			case "search":
				// cut last argument - page number and convert to int
				kw, p := splitLast(rawCmd)
				page, _ := strconv.Atoi(p)
				res, kb = searchHandler(kw, page)
			case "config":
				res, kb = configHandler(rawCmd, uid, msg.MessageID)
			case "tickets":
				res, kb = ticketsHandler(rawCmd, uid)
			case "comment":
				res, kb = commentHandler(rawCmd, uid, msg.MessageID)
			case "tag":
				res, kb = tagHandler(rawCmd, uid)
			case "close":
				// delete message on close button
				_, err := Bot.Request(tgbotapi.NewDeleteMessage(uid, msg.MessageID))
				if err != nil {
					logError(fmt.Sprintf("[close] %v", err))
					res = fmtErr(err.Error())
				} else {
					continue
				}
			default:
				logWarning(fmt.Sprintf("[callback] wrong mode: %s", mode))
				goto CALLBACK
			}

			// edit message
			if len(kb.InlineKeyboard) > 0 {
				editTextAndKeyboard(msg, res, kb)
			} else {
				editTextRemoveKeyboard(msg, res)
			}
		CALLBACK:
			Bot.Request(tgbotapi.NewCallback(u.CallbackQuery.ID, "Done"))
		}
	}
}
