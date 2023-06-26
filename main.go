package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
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
	BotToken        string `yaml:"bot_token"`
	UseWebhook      bool   `yaml:"use_webhook"`
	WebhookURL      string `yaml:"webhook_url"`
	ListenPort      string `yaml:"listen_port"`
	Admin           int64  `yaml:"admin"`
	InkoToolsAPI    string `yaml:"inkotools_api_url"`
	DebugMode       bool   `yaml:"debug"`
	MaintenanceMode bool   `yaml:"maintenance"`
	MaintenanceMsg  string `yaml:"maintenance_message"`
}

// UserConfig struct
type UserConfig struct {
	Name string `yaml:"name"`
}

// UserData struct
type UserData struct {
	Mode string // command mode
	TMP  string // to save temporary data between messages
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
	LinkDownCount int
	LastLogEvent  string
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

// LogEvent type
type LogEvent struct {
	Time     time.Time `mapstructure:"timestamp"`
	LogLevel string    `mapstructure:"log_level"`
	Message  string    `mapstructure:"message"`
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
<code>SW_IP</code> - get switch summary
<code>SW_IP PORT</code> - get port info
<code>SW_IP free</code> - get free ports
<code>/ping IP</code> - ping
<code>/calc IP</code> - ip calc

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

// BotCommands const
var BotCommands = []tgbotapi.BotCommand{
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

// convert UTC to MSK
func utc2msk(t time.Time) time.Time {
	loc, _ := time.LoadLocation("Europe/Moscow")
	return t.In(loc)
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
	// init cron
	Cron = cron.New()
	// clear switches pool daily
	id, err := Cron.AddFunc("0 0 * * *", func() { apiDelete("/pool") })
	if err != nil {
		logError(fmt.Sprintf("[init] [cron] failed to add clear pool entry: %v", err))
	} else {
		logInfo(fmt.Sprintf("[init] [cron] added clear pool entry daily [%d]", id))
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

// init empty user data
func initUserData(uid int64) {
	Data[uid] = &UserData{}
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
		"fmtHTML": html.EscapeString,
		"inc":     func(x int) int { return x + 1 },
		"add":     func(x, y int) int { return x + y },
		"utc2msk": utc2msk,
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

// generate pagination keyboard row for page/total
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

// generate pagination keyboard row for offset/limit
func rowOffsetLimit(cmd string, offset int, limit int, isLastPage bool) [][]map[string]string {
	// current (refresh)
	buttons := [][]map[string]string{{
		{fmt.Sprintf("[%d-%d]", offset+1, offset+limit): fmt.Sprintf("%s %d", cmd, offset)},
	}}
	// next button
	if !isLastPage {
		buttons[0] = append(buttons[0], map[string]string{
			fmt.Sprintf("[%d-%d] >", offset+limit+1, offset+limit*2): fmt.Sprintf("%s %d", cmd, offset+limit),
		})
	}
	// prev button
	if offset > limit {
		buttons[0] = append(
			[]map[string]string{{fmt.Sprintf("< [%d-%d]", offset-limit+1, offset): fmt.Sprintf("%s %d", cmd, offset-limit)}},
			buttons[0]...)
	}
	// first button
	if offset > 0 {
		buttons[0] = append(
			[]map[string]string{{fmt.Sprintf("<< [1-%d]", limit): fmt.Sprintf("%s 0", cmd)}},
			buttons[0]...)
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

// get switch free ports and format them with template
func freePorts(ip string) (string, error) {
	var res string
	var ports []Port

	resp, err := apiGet(fmt.Sprintf("/sw/%s/freeports/", ip))
	if err != nil {
		return res, err
	}
	mapstructure.Decode(resp["data"], &ports)
	if len(ports) == 0 {
		res = "\n<code>Not found</code>"
	} else {
		res = fmtObj(ports, "port")
	}
	return res, err
}

// get switch access ports and format them with template
func accessPorts(ip string) (string, error) {
	var res string
	var ports []Port

	resp, err := apiGet(fmt.Sprintf("/sw/%s/accessports/", ip))
	if err != nil {
		return res, err
	}
	mapstructure.Decode(resp["data"], &ports)
	if len(ports) == 0 {
		res = "No access ports found"
	} else {
		res = fmtObj(ports, "port")
	}
	return res, err
}

// get last logs from api and format with template
func getLastLogs(endpoint string, offset int, limit int) (string, bool, error) {
	var res string
	var events []LogEvent

	resp, err := apiGet(fmt.Sprintf("%s/log?offset=%d&limit=%d", endpoint, offset, limit))
	if err != nil {
		return res, true, err
	}
	mapstructureDecode(resp["data"], &events)
	res = fmtObj(events, "log.tmpl")
	isLastPage := len(events) < limit
	return res, isLastPage, err
}

// shortcut for switch logs
func swLogs(ip string, offset int, limit int) (string, bool, error) {
	return getLastLogs(fmt.Sprintf("/sw/%s", ip), offset, limit)
}

// shortcut for port logs
func portLogs(ip string, port string, offset int, limit int) (string, bool, error) {
	return getLastLogs(fmt.Sprintf("/sw/%s/ports/%s", ip, port), offset, limit)
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

	// get linkdown count
	resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/linkdowncount", ip, port))
	if err == nil {
		mapstructure.Decode(resp["data"], &pInfo.LinkDownCount)
	}

	// get last log event
	s, _, err := portLogs(ip, port, 0, 1)
	pInfo.LastLogEvent = strings.Trim(s, "\n")

	// get port counters
	resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/counters", ip, port))
	if err != nil {
		pInfo.Counters.Error = err.Error()
	} else {
		mapstructure.Decode(resp["data"], &pInfo.Counters)
	}

	// check if port is transit
	portIsTransit := false
	// get list of access ports
	resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/", ip))
	if err == nil {
		mapstructure.Decode(resp["data"].(map[string]interface{})["access_ports"], &accessPorts)
	}
	if !intInList(pInfo.PortNumber, accessPorts) {
		portIsTransit = true
	}

	// get mac table only if link is up
	if pInfo.LinkUp {
		if portIsTransit {
			pInfo.MAC.Error = "Transit ports are not supported"
		} else {
			resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/mac", ip, port))
			if err != nil {
				pInfo.MAC.Error = err.Error()
			} else {
				mapstructure.Decode(resp["data"], &pInfo.MAC.Entries)
			}
		}
	}

	// all other data for full style
	if style == "full" {

		// get port bandwidth
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/bandwidth", ip, port))
		if err == nil {
			mapstructure.Decode(resp["data"], &pInfo.Bandwidth)
		}

		// get vlan
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/vlan", ip, port))
		if err != nil {
			pInfo.VLAN.Error = err.Error()
		} else {
			mapstructure.Decode(resp["data"], &pInfo.VLAN)
		}

		// all other data only for access ports
		if portIsTransit {
			e := "Transit ports are not supported"
			pInfo.ACL.Error = e
			pInfo.Multicast.Error = e
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

			// get arp only if mac address table is not empty and not more than 5 addresses
			if x := len(pInfo.MAC.Entries); x > 0 && x < 5 {
				// get arp table for acl permit ip
				for _, a := range pInfo.ACL.Entries {
					if a.Mode == "permit" {
						if a.IP == "0.0.0.0" {
							// skip arpsearch for 0.0.0.0
							logWarning(fmt.Sprintf("[%s][%s] Invalid permit ACL", ip, port))
							continue
						}
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

	res += fmtObj(pInfo, "port.tmpl")
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
	case "maintenance":
		switch arg {
		case "on":
			CFG.MaintenanceMode = true
		case "off":
			CFG.MaintenanceMode = false
		}
		res = fmt.Sprintf("Maintenance: %v", CFG.MaintenanceMode)
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
			res, kb = swHandler(ip, args)
			// ip is client ip
		} else {
			res = fmt.Sprintf("%s is not a switch ip", ip)
		}
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
func swHandler(ip string, args string) (string, tgbotapi.InlineKeyboardMarkup) {
	var res string // text message result
	var err error
	var kb tgbotapi.InlineKeyboardMarkup // inline keyboard markup
	pView := []string{"short", "full"}   // view styles for port summary
	idx := 0                             // default index - short view
	// offset := 0                          // start offset for logs
	limit := 5 // default limit for logs
	logDebug(fmt.Sprintf("[swHandler] ip: %s, args: '%s'", ip, args))
	port := ""
	// check first arg
	action, args := splitArgs(args)
	switch action {
	// free ports handler
	case "free":
		res += "Free ports:"
		s, err := freePorts(ip)
		if err != nil {
			res += fmt.Sprintf("\n<code>%s</code>", err.Error())
		} else {
			res += s
			kb = genKeyboard([][]map[string]string{{
				{ip: fmt.Sprintf("raw edit %s", ip)},
				{"close": "close"},
			}})
		}
		return res, kb
	// access ports handler
	case "access":
		s, err := accessPorts(ip)
		if err != nil {
			res += fmt.Sprintf("\n<code>%s</code>", err.Error())
		} else {
			res += s
			// Generate buttons for each port
			pCnt := strings.Count(s, "Port:")
			var buttons [][]map[string]string
			var row []map[string]string
			inRow := calcRowLength(pCnt)
			for p := 1; p <= pCnt; p++ {
				row = append(row, map[string]string{strconv.Itoa(p): fmt.Sprintf("raw send %s %d", ip, p)})
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
			buttons = append(buttons, []map[string]string{
				{ip: fmt.Sprintf("raw edit %s", ip)},
				{"close": "close"},
			})
			kb = genKeyboard(buttons)
		}
		return res, kb
	// switch logs handler
	case "log":
		o, _ := splitArgs(args)
		offset, _ := strconv.Atoi(o)
		res += fmt.Sprintf("events [%d - %d]:", offset+1, offset+limit)
		s, isLastPage, err := swLogs(ip, offset, limit)
		if err != nil {
			res += fmt.Sprintf("\n<code>%s</code>", err.Error())
		} else {
			res += s
			// first row with pagination
			buttons := rowOffsetLimit(fmt.Sprintf("raw edit %s log", ip), offset, limit, isLastPage)
			// second row
			buttons = append(buttons, []map[string]string{
				{ip: fmt.Sprintf("raw edit %s", ip)},
				{"close": "close"},
			})
			kb = genKeyboard(buttons)
		}
		return res, kb
	// check if first arg is port
	default:
		if _, err := strconv.Atoi(action); err != nil {
			// empty or invalid port - return full sw info
			res, err = swSummary(ip, "full")
			// logs are displayed even if switch is not available
			if err == nil || err.Error() == "unavailable" {
				buttons := [][]map[string]string{
					{
						{"switch log": fmt.Sprintf("raw edit %s log", ip)},
					},
					{
						{"refresh": fmt.Sprintf("raw edit %s", ip)},
						{"close": "close"},
					},
				}
				// if switch is available - add free and access ports buttons
				if err == nil {
					buttons = append([][]map[string]string{{
						{"free ports": fmt.Sprintf("raw edit %s free", ip)},
						{"access ports": fmt.Sprintf("raw edit %s access", ip)},
					}}, buttons...)
				}
				kb = genKeyboard(buttons)
			}
			return res, kb
		}
		// else - go next to port handler
		port = action
	}
	// port logs handler
	if a, o := splitArgs(args); a == "log" {
		offset, _ := strconv.Atoi(o)
		res += fmt.Sprintf("events [%d - %d]:", offset+1, offset+limit)
		s, isLastPage, err := portLogs(ip, port, offset, limit)
		if err != nil {
			res += fmt.Sprintf("\n<code>%s</code>", err.Error())
		} else {
			res += s
			// first row with pagination
			buttons := rowOffsetLimit(fmt.Sprintf("raw edit %s %s log", ip, port), offset, limit, isLastPage)
			// second row
			buttons = append(buttons, []map[string]string{
				{fmt.Sprintf("%s %s", ip, port): fmt.Sprintf("raw edit %s %s", ip, port)},
				{"close": "close"},
			})
			kb = genKeyboard(buttons)
		}
		return res, kb
	}
	// for ports switch view is always short
	res, err = swSummary(ip, "short")
	// no need to check port if switch is unavailable
	if err != nil {
		return res, kb
	}
	// clear counters if needed
	if strings.Contains(args, "clear") {
		logDebug(fmt.Sprintf("[swHandler] Clear result: %s", portClear(ip, port)))
	}
	if strings.Contains(args, "full") {
		idx = 1
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
			{"port log": fmt.Sprintf("raw edit %s %s log", ip, port)},
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

			// workaround to remove orphan cancel button
			if msg == "cancel" && Data[uid].Mode != "comment" {
				logWarning("[orphan] cancel removed")
				clearReplyKeyboard(uid)
				goto SEND
			}

			// stop pinger outside pinger mode
			if msg == "stop" && Data[uid].Mode != "ping" {
				logWarning("[orphan] pinger stopped")
				pingerStop(uid)
				goto SEND
			}

			if cmd != "" {
				// reset mode for each new command
				Data[uid].Mode = ""
				// clear TMP for non-interactive commands
				if cmd != "comment" && cmd != "config" {
					Data[uid].TMP = ""
				}
			}

			// maintenance mode
			if CFG.MaintenanceMode && uid != CFG.Admin {
				res, kb = CFG.MaintenanceMsg, closeButton()
				goto SEND
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
			case "raw":
				Data[uid].Mode = cmd
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

			// maintenance mode
			if CFG.MaintenanceMode && uid != CFG.Admin && mode != "close" {
				mode = "maintenance"
			}

			switch mode {
			case "raw":
				res, kb = rawHandler(rawCmd)
			case "search":
				// cut last argument - page number and convert to int
				kw, p := splitLast(rawCmd)
				page, _ := strconv.Atoi(p)
				res, kb = searchHandler(kw, page)
			case "close":
				// delete message on close button
				msgDate := time.Unix(int64(msg.Date), 0)
				if time.Since(msgDate) > time.Hour*48 {
					logWarning("[close] Message is older than 48h")
					res = "<b>Bot cannot delete messages older than 48 hours!</b> \n\n" +
						"<i>This is is a telegram api limitation. You can delete this message manually.</i> \n\n" +
						"<code>https://core.telegram.org/bots/api#deletemessage</code>"
				} else {
					_, err := Bot.Request(tgbotapi.NewDeleteMessage(uid, msg.MessageID))
					if err != nil {
						logError(fmt.Sprintf("[close] %v", err))
						res = fmtErr(err.Error())
					} else {
						continue
					}
				}
			case "maintenance":
				res, kb = CFG.MaintenanceMsg, closeButton()
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
