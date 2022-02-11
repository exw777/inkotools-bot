package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// CFGFILE - path to config file
const CFGFILE string = "config.yml"

// Config struct
type Config struct {
	BotToken     string           `yaml:"bot_token"`
	WebhookURL   string           `yaml:"webhook_url"`
	ListenPort   string           `yaml:"listen_port"`
	Admin        int64            `yaml:"admin"`
	Users        map[int64]string `yaml:"users"`
	InkoToolsAPI string           `yaml:"inkotools_api_url"`
	DebugMode    bool             `yaml:"debug"`
}

// CFG - config object
var CFG Config

// TPL - templates object
var TPL *template.Template

// Bot - bot object
var Bot *tgbotapi.BotAPI

// Switch type
type Switch struct {
	IP       string `mapstructure:"ip"`
	Location string `mapstructure:"location"`
	MAC      string `mapstructure:"mac"`
	Model    string `mapstructure:"model"`
	Status   bool   `mapstructure:"status"`
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
}

// Pair type - pair in cable
type Pair struct {
	Pair  int    `mapstructure:"pair"`
	State string `mapstructure:"state"`
	Len   int    `mapstructure:"len"`
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
}

// XCHAR - unicode symbol X
const XCHAR string = "\xE2\x9D\x8C"

// VCHAR - unicode symbol V
const VCHAR string = "\xE2\x9C\x85"

// FAILCHAR - unicode symbol crossed circle
const FAILCHAR string = "\xF0\x9F\x9A\xAB"

// OKCHAR - unicode symbol OK
const OKCHAR string = "\xF0\x9F\x86\x97"

// UPCHAR - unicode symbol UP
const UPCHAR string = "\xF0\x9F\x86\x99"

// WARNCHAR - unicode symbol !!
const WARNCHAR string = "\xE2\x80\xBC"

// HELPUSER - help string for user
const HELPUSER string = `
Switch commands:
<code>IP</code> - get switch full summary
<code>IP PORT</code> - get short switch and short port summary
<code>IP PORT ARGS</code> - pass additional arguments

<b><i>IP</i></b> can be in short or full format (e.g. <code>59.75</code> and <code>192.168.59.75</code> are equal)

Each <b><i>argument</i></b> can be in abbreviated form (e.g. <code>cl</code> and <code>clear</code> are equal)

Supported arguments:
<code>clear</code> - clear port counters
<code>full</code> - print additional port information

Client commands:
<code>IP</code> - get client ip address summary (ip, mask, gateway, prefix)

<b>Other commands:</b>
/help - print this help
`

// HELPADMIN - help string for admin
const HELPADMIN string = `
<code>/admin list</code> - list authorized users
<code>/admin add ID [NAME]</code> - add user with id <b><i>ID</i></b> and optional mark with comment <b><i>NAME</i></b>
<code>/admin del ID</code> - delete user with id <b><i>ID</i></b>
<code>/admin send ID TEXT</code> - send message <b><i>TEXT</i></b> to user with id <b><i>ID</i></b>
<code>/admin broadcast TEXT</code> - send broadcast message <b><i>TEXT</i></b> 
<code>/admin reload</code> - reload configuration from file
`

// HELPER FUNCTIONS

// check if uid is in users map
func userIsAuthorized(id int64) bool {
	_, ok := CFG.Users[id]
	return ok
}

// split first arg from args
func splitArgs(args string) (first string, other string) {
	a := strings.SplitN(args, " ", 2)
	if len(a) < 2 {
		return a[0], ""
	}
	return a[0], strings.TrimSpace(a[1])
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
	return "\n<b>ERROR</b>" + WARNCHAR + "\n<code>" + e + "</code>\n"
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
	for ; res >= ratio && i < len(units); i++ {
		res /= ratio
	}
	return fmt.Sprintf("%.2f %s", res, units[i])
}

// debug log
func logDebug(msg string) {
	if CFG.DebugMode {
		log.Printf("[DEBUG]%s", msg)
	}
}

// print timestamp
func printUpdated() string {
	t := time.Now().Format("2006-01-02 15:04:05")
	return fmt.Sprintf("\n<i>Updated:</i> <code>%s</code>", t)
}

// MAIN FUNCTIONS

// init telegram bot
func initBot() tgbotapi.UpdatesChannel {
	var err error
	Bot, err = tgbotapi.NewBotAPI(CFG.BotToken)
	if err != nil {
		log.Panic(err)
	}
	Bot.Debug = CFG.DebugMode
	log.Printf("Authorized on bot account %s", Bot.Self.UserName)

	whInfo, _ := Bot.GetWebhookInfo()
	logDebug(fmt.Sprintf("Got webhook info: %v", whInfo.URL))
	// check webhook is set
	if whInfo.URL != CFG.WebhookURL+Bot.Token {
		logDebug(fmt.Sprintf("New webhook: %s", CFG.WebhookURL+Bot.Token))
		wh, _ := tgbotapi.NewWebhook(CFG.WebhookURL + Bot.Token)
		_, err := Bot.Request(wh)
		if err != nil {
			log.Panic(err)
		}
	}
	// serve http
	go http.ListenAndServe(":"+CFG.ListenPort, nil)
	updates := Bot.ListenForWebhook("/" + Bot.Token)
	log.Printf("Listening on port %s", CFG.ListenPort)
	return updates
}

// load config from file
func loadConfig() error {
	data, err := ioutil.ReadFile(CFGFILE)
	if err != nil {
		log.Printf("Read config file error: %v", err)
		return err
	}
	err = yaml.Unmarshal(data, &CFG)
	if err != nil {
		log.Printf("Parse yaml error: %v", err)
		return err
	}
	log.Printf("Config loaded from %s", CFGFILE)
	// Template functions
	funcMap := template.FuncMap{
		"fmtBytes": fmtBytes,
	}
	// load templates
	TPL, err = template.New("templates").Funcs(funcMap).ParseGlob("templates/*")
	if err != nil {
		log.Printf("Parse templates error: %v", err)
		return err
	}
	for _, t := range TPL.Templates() {
		logDebug(fmt.Sprintf("Loaded template: %v", t.Name()))
	}
	return nil
}

// write config to file
func saveConfig() error {
	data, err := yaml.Marshal(&CFG)
	if err != nil {
		log.Printf("YAML marshal error: %v", err)
		return err
	}
	// attach document start and end strings
	data = append([]byte("---\n"), data...)
	data = append(data, []byte("...\n")...)
	err = ioutil.WriteFile(CFGFILE, data, 0644)
	if err != nil {
		log.Printf("Write config error: %v", err)
		return err
	}
	log.Printf("Config saved to %s", CFGFILE)
	return nil
}

// add/delete user
func manageUser(args string, enabled bool) {
	u, name := splitArgs(args)
	uid, err := strconv.ParseInt(u, 10, 64)
	if err != nil || uid == 0 {
		return
	}
	var msgUser, msgAdmin string
	if enabled && !userIsAuthorized(uid) {
		CFG.Users[uid] = name
		msgUser = "You are added to authorized users list."
		msgAdmin = fmt.Sprintf("User <code>%d</code> <b>%s</b> added.",
			uid, CFG.Users[uid])
	} else if !enabled && userIsAuthorized(uid) {
		delete(CFG.Users, uid)
		msgUser = "You are removed from authorized users list."
		msgAdmin = fmt.Sprintf("User <code>%d</code> <b>%s</b> removed.",
			uid, CFG.Users[uid])
	} else {
		return
	}
	logDebug(msgAdmin)
	saveConfig()
	sendTo(uid, msgUser)
	sendTo(CFG.Admin, msgAdmin)
}

// send text message to user
func sendTo(id int64, text string) (tgbotapi.Message, error) {
	msg := tgbotapi.NewMessage(id, text)
	msg.ParseMode = tgbotapi.ModeHTML
	res, err := Bot.Send(msg)
	if err != nil {
		log.Printf("Error sendTo[%d]: %v", id, err)
	}
	return res, err
}

// broadcast message to all users
func broadcastSend(text string) {
	if text == "" {
		sendTo(CFG.Admin, fmtErr("empty message"))
		return
	}
	for uid := range CFG.Users {
		sendTo(uid, text)
	}
}

// universal api request
func requestAPI(method string, endpoint string, args map[string]interface{}) (map[string]interface{}, error) {
	logDebug(fmt.Sprintf("API %s request endpoint: %s args: %v", method, endpoint, args))
	var res map[string]interface{}
	if endpoint == "" {
		return res, errors.New("Empty endpoint")
	}
	// pack arguments to body
	var reqBody *bytes.Buffer
	if len(args) > 0 {
		reqData, err := json.Marshal(args)
		if err != nil {
			log.Printf("Pack args to json error: %v", err)
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
		log.Printf("Make request error: %v", err)
		return res, errors.New("Making request failed")
	}
	req.Header.Add("Content-Type", "application/json")
	// send json request to api
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("API request error: %v", err)
		return res, errors.New("API request failed")
	}
	defer resp.Body.Close()
	// parse response
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		log.Printf("Json decode error: %v", err)
		return res, errors.New("API response decode failed")
	}
	// if we have no errors from api - return result
	if resp.StatusCode < 400 {
		logDebug(fmt.Sprintf("API response: %v", res))
		return res, nil
	}
	// parse errors from api
	if res["detail"] != nil {
		log.Printf("API returned %d error: %v", resp.StatusCode, res["detail"])
		switch res["detail"].(type) {
		case string:
			return res, errors.New(res["detail"].(string))
		case []interface{}:
			return res, fmt.Errorf("%d", resp.StatusCode)
		}
	}
	log.Printf("API returned %d error, raw response: %v", resp.StatusCode, res)
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
func swSummary(ip string, style string) string {
	var template string
	switch style {
	case "short":
		template = "sw.short.tmpl"
	default:
		template = "sw.tmpl"
	}
	resp, err := apiGet(fmt.Sprintf("/sw/%s/", ip))
	if err != nil {
		return fmtErr(err.Error())
	}
	// serialize data from returned map to struct
	var sw Switch
	mapstructure.Decode(resp["data"], &sw)
	res := fmtObj(sw, template)
	if !sw.Status {
		res += fmtErr("Switch is unavailable!")
	}
	return res
}

// get port summary and format it with template
func portSummary(ip string, port string, style string) string {
	var res string
	var ports []Port
	var linkUp bool
	var counters PortCounters
	resp, err := apiGet(fmt.Sprintf("/sw/%s/ports/%s/", ip, port))
	if err != nil {
		return fmtErr(err.Error())
	}
	// returned value is list (for combo ports - two values)
	mapstructure.Decode(resp["data"], &ports)
	// format ports summary
	res += fmtObj(ports, "ports.tmpl")
	for p := range ports {
		if ports[p].Link {
			linkUp = true
			break
		}
	}
	//get port counters
	resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/counters", ip, port))
	if err == nil {
		mapstructure.Decode(resp["data"], &counters)
		res += fmtObj(counters, "counters.tmpl")
	}
	if style == "full" {
		var v PortVlan
		var acl []PortACL
		var macTable []PortMac
		var arpTable []ARPEntry
		var arpTmp []ARPEntry
		var accessPorts []int
		// get vlan
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/vlan", ip, port))
		if err == nil {
			mapstructure.Decode(resp["data"], &v)
			res += fmtObj(v, "vlan.tmpl")
		}
		// acl, mac and arp only for access ports
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/", ip))
		if err == nil {
			mapstructure.Decode(resp["data"].(map[string]interface{})["access_ports"], &accessPorts)
		}
		if sort.SearchInts(accessPorts, ports[0].Port) == len(accessPorts) {
			goto END
		}
		// get acl
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/acl", ip, port))
		if err == nil {
			mapstructure.Decode(resp["data"], &acl)
			res += fmtObj(acl, "acl.tmpl")
		}
		// get mac table only if link is up
		if !linkUp {
			goto END
		}
		resp, err = apiGet(fmt.Sprintf("/sw/%s/ports/%s/mac", ip, port))
		if err == nil {
			mapstructure.Decode(resp["data"], &macTable)
			res += fmtObj(macTable, "mac.tmpl")
		}
		// only if mac address table is not empty
		if len(macTable) == 0 {
			goto END
		}
		// get arp table for acl permit ip
		for _, a := range acl {
			if a.Mode == "permit" {
				resp, err = requestAPI("POST", "/arpsearch", map[string]interface{}{"ip": a.IP})
				if err == nil {
					mapstructure.Decode(resp["data"], &arpTmp)
					// append to global arp
					arpTable = append(arpTable, arpTmp...)
				} else {
					res += fmtErr("Failed to get arp by ip")
				}
			}
		}
		// get arp for each mac address
		for _, m := range macTable {
			resp, err = requestAPI("POST", "/arpsearch", map[string]interface{}{"mac": m.Mac, "src_sw_ip": ip})
			if err == nil {
				mapstructure.Decode(resp["data"], &arpTmp)
				// append to global arp
				arpTable = append(arpTable, arpTmp...)
			} else {
				res += fmtErr("Failed to get arp by mac")
			}
		}
		// remove duplicate entries from global arp table
		arpTmp = arpTable
		arpTable = nil
		for _, a := range arpTmp {
			dup := false
			for _, u := range arpTable {
				if u == a {
					dup = true
					break
				}
			}
			if !dup {
				arpTable = append(arpTable, a)
			}
		}

		res += fmtObj(arpTable, "arp.tmpl")

	END:
	}
	res += printUpdated()

	return res
}

// clear port counters
func portClear(ip string, port string) string {
	resp, err := apiDelete(fmt.Sprintf("/sw/%s/ports/%s/counters", ip, port))
	if err != nil {
		return fmtErr(err.Error())
	}
	if resp["detail"] == nil {
		log.Printf("[Clear %s %s]API returned no detail, raw data: %v", ip, port, resp)
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

// start command handler
func cmdStartHandler(u tgbotapi.Update) {
	user := u.Message.From
	if userIsAuthorized(user.ID) {
		cmdHelpHandler(u)
	} else {
		msg := fmt.Sprintf("User <b>%s</b> requests authorization:\n"+
			"id: <code>%d</code>", user, user.ID)
		sendTo(CFG.Admin, msg)
	}
}

// help command handler
func cmdHelpHandler(u tgbotapi.Update) {
	uid := u.Message.From.ID
	if !userIsAuthorized(uid) && uid != CFG.Admin {
		cmdStartHandler(u)
	}
	msg := "<b>Available commands:</b>\n"
	if uid == CFG.Admin {
		msg += HELPADMIN
	}
	if userIsAuthorized(uid) {
		msg += HELPUSER
	}
	sendTo(uid, msg)
}

// admin command handler
func cmdAdminHandler(u tgbotapi.Update) {
	// exit if user is not admin
	if u.Message.From.ID != CFG.Admin {
		return
	}
	cmd, arg := splitArgs(u.Message.CommandArguments())
	switch cmd {
	case "list":
		var lst string
		for id, name := range CFG.Users {
			lst += fmt.Sprintf("<code>%d</code> - %s\n", id, name)
		}
		sendTo(CFG.Admin, lst)
	case "add":
		manageUser(arg, true)
	case "del":
		manageUser(arg, false)
	case "send":
		user, text := splitArgs(arg)
		id, _ := strconv.ParseInt(user, 10, 64)
		sendTo(id, text)
	case "broadcast":
		broadcastSend(arg)
	case "reload":
		loadConfig()
	default:
		cmdHelpHandler(u)
	}
}

// parse raw input handler
func rawInputHandler(u tgbotapi.Update) {
	var uid int64
	var rawInput string
	var action string
	if u.CallbackQuery != nil {
		uid = u.CallbackQuery.Message.Chat.ID
		action, rawInput = splitArgs(u.CallbackQuery.Data)

	} else {
		uid = u.Message.From.ID
		rawInput = u.Message.Text
		action = "send"
	}
	if !userIsAuthorized(uid) && uid != CFG.Admin {
		return
	}

	var res string // answer to user
	cmd, args := splitArgs(rawInput)
	// check if cmd is ip
	ip := fullIP(cmd, false)
	if ip != "" {
		if fullIP(ip, true) != "" {
			// ip is sw ip
			port, args := splitArgs(args)
			if action == "clear" {
				portClear(ip, port)
				action = "refresh"
			}
			res = swHandler(ip, port, args)
			goto SEND
		}
		// ip is client ip
		res = ipHandler(ip, args)
		goto SEND
	}

	logDebug(fmt.Sprintf("user: %s, cmd: %s, args: %s", CFG.Users[uid], cmd, args))
	res = fmt.Sprintf("Original message: %s", rawInput)

SEND:
	if res == "" {
		return
	}
	log.Printf("[%s] %s %s", CFG.Users[uid], action, rawInput)
	if action == "refresh" {
		cb := tgbotapi.NewCallback(u.CallbackQuery.ID, u.CallbackQuery.Data)
		if _, err := Bot.Request(cb); err != nil {
			log.Printf("Error sending callback to [%d]: %v", uid, err)
		}
		msg := tgbotapi.NewEditMessageTextAndMarkup(
			u.CallbackQuery.Message.Chat.ID,
			u.CallbackQuery.Message.MessageID,
			res,
			*u.CallbackQuery.Message.ReplyMarkup)
		msg.ParseMode = tgbotapi.ModeHTML
		_, err := Bot.Send(msg)
		if err != nil {
			log.Printf("Error sending updated message to [%d]: %v", uid, err)
		}
	} else {
		msg := tgbotapi.NewMessage(uid, "")
		msg.ParseMode = tgbotapi.ModeHTML
		if strings.Contains(res, "Updated:") {
			kb := tgbotapi.NewInlineKeyboardMarkup(
				tgbotapi.NewInlineKeyboardRow(
					tgbotapi.NewInlineKeyboardButtonData("refresh", "refresh "+rawInput),
					tgbotapi.NewInlineKeyboardButtonData("clear", "clear "+rawInput),
					tgbotapi.NewInlineKeyboardButtonData("repeat", "repeat "+rawInput),
				),
			)
			msg.ReplyMarkup = kb
		}
		msg.Text = res

		_, err := Bot.Send(msg)
		if err != nil {
			log.Printf("Error sending message to [%d]: %v", uid, err)
		}
	}
}

// switch ip handler
func swHandler(ip string, port string, args string) string {
	var res string
	switch {
	case port == "":
		res = swSummary(ip, "full")
	case args == "":
		res = swSummary(ip, "short")
		if !strings.Contains(res, "ERROR") {
			res += portSummary(ip, port, "short")
		}
	case strings.HasPrefix("full", args):
		res = swSummary(ip, "short")
		if !strings.Contains(res, "ERROR") {
			res += portSummary(ip, port, "full")
		}
	case strings.HasPrefix("clear", args):
		res = portClear(ip, port)
	default:
		res = ""
	}
	return res
}

// client ip handler
func ipHandler(ip string, args string) string {
	// dummy calculator
	return ipCalc(ip)
}

// MAIN APP
func main() {
	loadConfig()
	// serve telegram updates
	for update := range initBot() {
		// command messages
		if update.CallbackQuery != nil {
			rawInputHandler(update)
		} else if update.Message == nil {
			continue
		} else if update.Message.IsCommand() {
			cmd := update.Message.Command()
			switch cmd {
			case "start":
				cmdStartHandler(update)
			case "help":
				cmdHelpHandler(update)
			case "admin":
				cmdAdminHandler(update)
			default:
				cmdHelpHandler(update)
			}
		} else if update.Message != nil {
			rawInputHandler(update)
		}
	}
}
