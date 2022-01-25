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
	"strconv"
	"strings"

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

// Bot - bot object
var Bot *tgbotapi.BotAPI

// Switch type
type Switch struct {
	IP       string `json:"ip"`
	Location string `json:"location"`
	MAC      string `json:"mac"`
	Model    string `json:"model"`
	Status   bool   `json:"status"`
}

// some formatting constants
const XCHAR string = "\xE2\x9D\x8C"
const VCHAR string = "\xE2\x9C\x85"
const FAILCHAR string = "\xF0\x9F\x9A\xAB"
const OKCHAR string = "\xF0\x9F\x86\x97"
const UPCHAR string = "\xF0\x9F\x86\x99"
const WARNCHAR string = "\xE2\x80\xBC"

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
	return a[0], a[1]
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
	} else {
		return ""
	}

}

// print error in message
func fmtErr(e string) string {
	return "<b>ERROR</b>" + WARNCHAR + "\n<code>" + e + "</code>\n"
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
	log.Printf("Got webhook info: %v", whInfo.URL)
	// check webhook is set
	if whInfo.URL != CFG.WebhookURL+Bot.Token {
		log.Printf("New behook: %s", CFG.WebhookURL+Bot.Token)
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

// sw api request
func requestAPI(endpoint string, args map[string]interface{}) (map[string]interface{}, error) {
	var res map[string]interface{}
	if endpoint == "" {
		return res, errors.New("Empty endpoint")
	}
	var resp *http.Response
	var err error
	if len(args) == 0 {
		// if no args - use get method
		resp, err = http.Get(CFG.InkoToolsAPI + endpoint)
	} else {
		// pack args to json
		reqData, err := json.Marshal(args)
		if err != nil {
			log.Printf("Pack args to json error: %v", err)
			return res, errors.New("Packing arguments to json failed")
		}
		resp, err = http.Post(CFG.InkoToolsAPI+endpoint, "application/json", bytes.NewBuffer(reqData))
	}
	if err != nil {
		log.Printf("Send api error: %v", err)
		return res, errors.New("Response from api failed")
	}
	defer resp.Body.Close()
	// read body first (it can be invalid json)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil || body == nil {
		return res, errors.New("Read body failed")
	}
	err = json.Unmarshal(body, &res)
	if err != nil {
		// json is invalid -return raw body in error
		return res, errors.New(string(body))
	}
	return res, nil
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
	cmdUser := "<code>/sw IP</code> - print summary info and " +
		"availability status of switch with ip address <b><i>IP</i></b>\n\n" +
		"<b><i>IP</i></b> can be in short or full format " +
		"(e.g. <code>59.75</code> and <code>192.168.59.75</code> are equal)\n\n" +
		"<code>/help</code> - print this help\n"
	cmdAdmin := "<code>/admin list</code> - list authorized users\n" +
		"<code>/admin add ID [NAME]</code> - add user with id <b><i>ID</i></b> " +
		"and optional mark with comment <b><i>NAME</i></b>\n" +
		"<code>/admin del ID</code> - delete user with id <b><i>ID</i></b>\n" +
		"<code>/admin send ID TEXT</code> - send message <b><i>TEXT</i></b> " +
		"to user with id <b><i>ID</i></b>\n" +
		"<code>/admin reload</code> - reload configuration from file\n\n"
	uid := u.Message.From.ID
	if !userIsAuthorized(uid) && uid != CFG.Admin {
		return
	}
	msg := "<b>Available commands:</b>\n\n"
	if uid == CFG.Admin {
		msg += cmdAdmin
	}
	if userIsAuthorized(uid) {
		msg += cmdUser
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

// sw command handler
func cmdSwHandler(u tgbotapi.Update) {
	uid := u.Message.From.ID
	ip, _ := splitArgs(u.Message.CommandArguments())
	// check ip
	ip = fullIP(ip, true)
	if ip == "" {
		sendTo(uid, fmtErr("wrong ip"))
		return
	}
	resp, err := requestAPI("/sw/"+ip, map[string]interface{}{})
	if err != nil {
		log.Printf("API request error: %v", err)
		sendTo(uid, fmtErr(err.Error()))
		return
	}
	// serialize data from returned map to struct
	sw := Switch{}
	var res string
	err = mapstructure.Decode(resp, &sw)
	if err != nil {
		log.Printf("Parse API response error: %v", err)
		res = fmtErr("parse API response failed") +
			"<b>RAW RESULT:</b><pre>" + fmt.Sprintf("%v", resp) + "</pre>"
	} else {
		res = fmt.Sprintf("ip: <code>%s</code>\nmac: <code>%s</code>\n"+
			"model: <code>%s</code>\nlocation: <code>%s</code>\nstatus: ",
			sw.IP, sw.MAC, sw.Model, sw.Location)
		if sw.Status {
			res = res + UPCHAR
		} else {
			res = res + FAILCHAR
		}
	}
	sendTo(uid, res)
}

// MAIN APP
func main() {
	loadConfig()
	// serve telegram updates
	for update := range initBot() {
		// ignore any non-Message updates
		if update.Message == nil {
			continue
		}
		// ignore any non-command Messages
		if !update.Message.IsCommand() {
			continue
		}
		cmd := update.Message.Command()
		switch cmd {
		case "start":
			cmdStartHandler(update)
		case "help":
			cmdHelpHandler(update)
		case "sw":
			cmdSwHandler(update)
		case "admin":
			cmdAdminHandler(update)
		default:
			cmdHelpHandler(update)
		}
	}
}
