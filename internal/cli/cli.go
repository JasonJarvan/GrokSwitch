package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bbbkawaii/GrokSwitch/internal/accounts"
	"github.com/bbbkawaii/GrokSwitch/internal/app"
	"github.com/bbbkawaii/GrokSwitch/internal/billing"
	"github.com/bbbkawaii/GrokSwitch/internal/grokauth"
)

var Version = "dev"

const usage = `GrokSwitch - manage and switch Grok Build accounts

Usage:
  grok-switch <command> [options]

Account commands:
  list, ls [--json] [--offline]
                              List accounts with Tier, quota, and reset time
  status [--json]             Show the active account and paths
  save [--alias NAME] [--json]
                              Save the current Grok login
  login [--alias NAME]        Log in through an isolated Grok auth file
        [--device-auth]
  import FILE [--alias NAME]  Import an auth.json or CPA OAuth file
        [--switch] [--cpa] [--json]
  switch, use [QUERY] [--json] [--offline]
                              Switch globally; prompts when QUERY is omitted
  previous [--json]           Switch back to the previous account
  alias QUERY NAME [--json]   Rename a saved account
  remove QUERY [--json]       Remove an account; active removal picks a fallback
  run QUERY [-- GROK_ARGS]    Run Grok with an isolated saved account

Diagnostics:
  doctor [--json]             Validate Grok, paths, and account snapshots
  version                     Print the GrokSwitch version
  help                        Show this help

Selectors:
  QUERY can be a row number, alias, email, account ID/prefix, or unique text.

Environment:
  GROK_HOME                   Grok home (default: ~/.grok)
  GROK_AUTH_PATH              Active auth file honored by Grok and GrokSwitch
  GROK_SWITCH_HOME            Account store (default: $GROK_HOME/accounts)
  GROK_SWITCH_GROK_BIN        Override the grok executable (useful for testing)
`

type options struct {
	values      map[string]string
	bools       map[string]bool
	positionals []string
	passthrough []string
}

func Run(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return 0
	}
	command := strings.ToLower(args[0])
	if command == "help" || command == "--help" || command == "-h" {
		fmt.Fprint(out, usage)
		return 0
	}
	if command == "version" || command == "--version" || command == "-v" {
		fmt.Fprintf(out, "grok-switch %s\n", resolvedVersion())
		return 0
	}
	if isKnownCommand(command) && hasHelpFlag(args[1:]) {
		fmt.Fprint(out, usage)
		return 0
	}

	paths, err := accounts.ResolvePaths()
	if err != nil {
		return fail(errOut, err)
	}
	application := app.New(paths, in, out, errOut)

	var runErr error
	switch command {
	case "list", "ls":
		runErr = commandList(application, args[1:], out)
	case "status":
		runErr = commandStatus(application, args[1:], out)
	case "save", "add":
		runErr = commandSave(application, args[1:], out)
	case "login":
		runErr = commandLogin(application, args[1:], out)
	case "import":
		runErr = commandImport(application, args[1:], out)
	case "switch", "use":
		runErr = commandSwitch(application, args[1:], in, out)
	case "previous", "prev":
		runErr = commandPrevious(application, args[1:], out)
	case "alias", "rename":
		runErr = commandAlias(application, args[1:], out)
	case "remove", "rm":
		runErr = commandRemove(application, args[1:], out)
	case "run":
		runErr = commandRun(application, args[1:])
	case "doctor":
		runErr = commandDoctor(application, args[1:], out)
	default:
		return fail(errOut, fmt.Errorf("unknown command %q; run 'grok-switch help'", args[0]))
	}

	if runErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitCode()
	}
	return fail(errOut, runErr)
}

func isKnownCommand(command string) bool {
	switch command {
	case "list", "ls", "status", "save", "add", "login", "import",
		"switch", "use", "previous", "prev", "alias", "rename", "remove",
		"rm", "run", "doctor":
		return true
	default:
		return false
	}
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func resolvedVersion() string {
	if value := strings.TrimSpace(Version); value != "" && value != "dev" {
		return strings.TrimPrefix(value, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		value := strings.TrimSpace(info.Main.Version)
		if value != "" && value != "(devel)" {
			return strings.TrimPrefix(value, "v")
		}
	}
	return "dev"
}

func commandList(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, nil, []string{"json", "offline"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 0 {
		return errors.New("list does not accept positional arguments")
	}
	list, err := application.List()
	if err != nil {
		return err
	}
	quotas := map[string]billing.Quota{}
	if !opts.bools["offline"] {
		quotas = application.FetchQuotas(list)
	}
	if opts.bools["json"] {
		payload := struct {
			ActiveAccountID string                   `json:"activeAccountId,omitempty"`
			Current         *grokauth.Identity       `json:"current,omitempty"`
			Accounts        []accounts.Account       `json:"accounts"`
			Quotas          map[string]billing.Quota `json:"quotas"`
		}{list.CurrentAccount, list.CurrentIdentity, list.Registry.Accounts, quotas}
		return writeJSON(out, payload)
	}
	printAccounts(out, list.Registry, list.CurrentAccount, quotas)
	if list.CurrentIdentity != nil && list.CurrentAccount == "" {
		fmt.Fprintln(out, "\nCurrent Grok login is not saved. Run: grok-switch save")
	}
	if list.CurrentError != nil {
		fmt.Fprintf(out, "\nWarning: active auth could not be read: %v\n", list.CurrentError)
	}
	return nil
}

func commandStatus(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, nil, []string{"json"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 0 {
		return errors.New("status does not accept positional arguments")
	}
	list, err := application.List()
	if err != nil {
		return err
	}
	activeAlias := ""
	previousAlias := ""
	if idx := accounts.IndexByID(list.Registry, list.CurrentAccount); idx >= 0 {
		activeAlias = list.Registry.Accounts[idx].Alias
	}
	if idx := accounts.IndexByID(list.Registry, list.Registry.PreviousAccountID); idx >= 0 {
		previousAlias = list.Registry.Accounts[idx].Alias
	}
	payload := struct {
		ActiveAlias      string             `json:"activeAlias,omitempty"`
		PreviousAlias    string             `json:"previousAlias,omitempty"`
		Current          *grokauth.Identity `json:"current,omitempty"`
		SavedAccounts    int                `json:"savedAccounts"`
		GrokHome         string             `json:"grokHome"`
		ActiveAuthPath   string             `json:"activeAuthPath"`
		AccountStorePath string             `json:"accountStorePath"`
		InlineAuthSet    bool               `json:"inlineAuthSet"`
		APIKeySet        bool               `json:"apiKeySet"`
	}{
		ActiveAlias:      activeAlias,
		PreviousAlias:    previousAlias,
		Current:          list.CurrentIdentity,
		SavedAccounts:    len(list.Registry.Accounts),
		GrokHome:         application.Paths.GrokHome,
		ActiveAuthPath:   application.Paths.ActiveAuth,
		AccountStorePath: application.Paths.StoreRoot,
		InlineAuthSet:    strings.TrimSpace(os.Getenv("GROK_AUTH")) != "",
		APIKeySet:        strings.TrimSpace(os.Getenv("XAI_API_KEY")) != "",
	}
	if opts.bools["json"] {
		return writeJSON(out, payload)
	}
	valueOr := func(value, fallback string) string {
		if value == "" {
			return fallback
		}
		return value
	}
	fmt.Fprintf(out, "Active:        %s\n", valueOr(payload.ActiveAlias, "not saved / signed out"))
	fmt.Fprintf(out, "Previous:      %s\n", valueOr(payload.PreviousAlias, "none"))
	fmt.Fprintf(out, "Saved:         %d account(s)\n", payload.SavedAccounts)
	fmt.Fprintf(out, "Grok home:     %s\n", payload.GrokHome)
	fmt.Fprintf(out, "Active auth:   %s\n", payload.ActiveAuthPath)
	fmt.Fprintf(out, "Account store: %s\n", payload.AccountStorePath)
	if payload.InlineAuthSet {
		fmt.Fprintln(out, "Warning: GROK_AUTH is set and overrides file-based switching.")
	}
	if payload.APIKeySet {
		fmt.Fprintln(out, "Note: XAI_API_KEY is set; saved session auth normally takes precedence.")
	}
	return nil
}

func commandSave(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, []string{"alias"}, []string{"json"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 0 {
		return errors.New("save does not accept positional arguments")
	}
	account, created, err := application.CaptureCurrent(opts.values["alias"])
	if err != nil {
		return err
	}
	if opts.bools["json"] {
		return writeJSON(out, struct {
			Created bool             `json:"created"`
			Account accounts.Account `json:"account"`
		}{created, *account})
	}
	verb := "Updated"
	if created {
		verb = "Saved"
	}
	fmt.Fprintf(out, "%s account %s%s.\n", verb, account.Alias, emailSuffix(account.Email))
	return nil
}

func commandLogin(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, []string{"alias"}, []string{"device-auth", "oauth"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 0 {
		return errors.New("login does not accept positional arguments")
	}
	if opts.bools["device-auth"] && opts.bools["oauth"] {
		return errors.New("choose only one of --device-auth or --oauth")
	}
	account, _, err := application.Login(opts.values["alias"], opts.bools["device-auth"])
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Active account: %s%s. Start Grok only after older global sessions are closed.\n", account.Alias, emailSuffix(account.Email))
	return nil
}

func commandImport(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, []string{"alias"}, []string{"switch", "cpa", "json"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 1 {
		return errors.New("usage: grok-switch import FILE [--alias NAME] [--switch] [--cpa]")
	}
	var account *accounts.Account
	var created bool
	var cpaInfo grokauth.CPAInfo
	if opts.bools["cpa"] {
		account, created, cpaInfo, err = application.ImportCPA(opts.positionals[0], opts.values["alias"], opts.bools["switch"])
	} else {
		account, created, err = application.Import(opts.positionals[0], opts.values["alias"], opts.bools["switch"])
	}
	if err != nil {
		return err
	}
	if opts.bools["json"] {
		return writeJSON(out, struct {
			Created            bool             `json:"created"`
			Active             bool             `json:"active"`
			Format             string           `json:"format"`
			SourceDisabled     bool             `json:"sourceDisabled,omitempty"`
			AccessTokenExpired bool             `json:"accessTokenExpired,omitempty"`
			Account            accounts.Account `json:"account"`
		}{created, opts.bools["switch"], importFormat(opts.bools["cpa"]), cpaInfo.SourceDisabled, cpaInfo.AccessTokenExpired, *account})
	}
	verb := "Updated"
	if created {
		verb = "Imported"
	}
	formatPrefix := ""
	if opts.bools["cpa"] {
		formatPrefix = "CPA "
	}
	fmt.Fprintf(out, "%s %saccount %s%s", verb, formatPrefix, account.Alias, emailSuffix(account.Email))
	if opts.bools["switch"] {
		fmt.Fprint(out, " and made it active; start Grok only after older global sessions are closed")
	}
	fmt.Fprintln(out, ".")
	if cpaInfo.SourceDisabled {
		fmt.Fprintln(out, "Warning: the CPA source marks this account disabled; the token bundle was imported for independent Grok validation.")
	}
	if cpaInfo.AccessTokenExpired {
		fmt.Fprintln(out, "Note: the CPA access token is expired; Grok must refresh it before use.")
	}
	return nil
}

func importFormat(cpa bool) string {
	if cpa {
		return "CPA"
	}
	return "auth.json"
}

func commandSwitch(application *app.App, args []string, in io.Reader, out io.Writer) error {
	opts, err := parseOptions(args, nil, []string{"json", "offline"})
	if err != nil {
		return err
	}
	if len(opts.positionals) > 1 {
		return errors.New("usage: grok-switch switch [QUERY]")
	}
	query := ""
	if len(opts.positionals) == 1 {
		query = opts.positionals[0]
	} else {
		if opts.bools["json"] {
			return errors.New("switch --json requires an explicit account query")
		}
		// Preserve a manually logged-in account before presenting the picker.
		_, _, captureErr := application.CaptureCurrent("")
		if captureErr != nil && !errors.Is(captureErr, app.ErrNoCurrentAuth) {
			return captureErr
		}
		list, err := application.List()
		if err != nil {
			return err
		}
		if len(list.Registry.Accounts) == 0 {
			return app.ErrNoAccounts
		}
		quotas := map[string]billing.Quota{}
		if !opts.bools["offline"] {
			quotas = application.FetchQuotas(list)
		}
		printAccounts(out, list.Registry, list.CurrentAccount, quotas)
		query, err = promptSelection(in, out, len(list.Registry.Accounts))
		if err != nil {
			return err
		}
	}
	account, err := application.Switch(query)
	if err != nil {
		return err
	}
	if opts.bools["json"] {
		return writeJSON(out, account)
	}
	fmt.Fprintf(out, "Switched to %s%s. Close older global Grok sessions before starting a new one.\n", account.Alias, emailSuffix(account.Email))
	return nil
}

func commandPrevious(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, nil, []string{"json"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 0 {
		return errors.New("previous does not accept positional arguments")
	}
	account, err := application.Previous()
	if err != nil {
		return err
	}
	if opts.bools["json"] {
		return writeJSON(out, account)
	}
	fmt.Fprintf(out, "Switched back to %s%s. Close older global Grok sessions before starting a new one.\n", account.Alias, emailSuffix(account.Email))
	return nil
}

func commandAlias(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, nil, []string{"json"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 2 {
		return errors.New("usage: grok-switch alias QUERY NAME")
	}
	account, err := application.Rename(opts.positionals[0], opts.positionals[1])
	if err != nil {
		return err
	}
	if opts.bools["json"] {
		return writeJSON(out, account)
	}
	fmt.Fprintf(out, "Account alias is now %s.\n", account.Alias)
	return nil
}

func commandRemove(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, nil, []string{"json"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 1 {
		return errors.New("usage: grok-switch remove QUERY")
	}
	removed, activated, err := application.Remove(opts.positionals[0])
	if err != nil {
		return err
	}
	if opts.bools["json"] {
		return writeJSON(out, struct {
			Removed          accounts.Account `json:"removed"`
			ActivatedAccount string           `json:"activatedAccount,omitempty"`
		}{*removed, activated})
	}
	fmt.Fprintf(out, "Removed account %s", removed.Alias)
	if activated != "" {
		fmt.Fprintf(out, "; switched to %s (close older global Grok sessions before starting a new one)", activated)
	}
	fmt.Fprintln(out, ".")
	return nil
}

func commandRun(application *app.App, args []string) error {
	opts, err := parseOptions(args, nil, nil)
	if err != nil {
		return err
	}
	if len(opts.positionals) != 1 {
		return errors.New("usage: grok-switch run QUERY [-- GROK_ARGS]")
	}
	return application.RunAccount(opts.positionals[0], opts.passthrough)
}

type doctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func commandDoctor(application *app.App, args []string, out io.Writer) error {
	opts, err := parseOptions(args, nil, []string{"json"})
	if err != nil {
		return err
	}
	if len(opts.positionals) != 0 {
		return errors.New("doctor does not accept positional arguments")
	}
	checks := []doctorCheck{}
	add := func(name string, ok bool, message string) {
		checks = append(checks, doctorCheck{Name: name, OK: ok, Message: message})
	}

	grokBin := strings.TrimSpace(os.Getenv("GROK_SWITCH_GROK_BIN"))
	if grokBin == "" {
		grokBin, err = exec.LookPath("grok")
	}
	if err != nil || grokBin == "" {
		add("grok", false, "grok executable not found in PATH")
	} else {
		version, versionErr := app.CommandOutput(grokBin, "--version")
		add("grok", versionErr == nil, valueOr(version, grokBin))
	}

	add("paths", filepath.IsAbs(application.Paths.GrokHome) && filepath.IsAbs(application.Paths.StoreRoot),
		"home="+application.Paths.GrokHome+" store="+application.Paths.StoreRoot)
	if strings.TrimSpace(os.Getenv("GROK_AUTH")) != "" {
		add("environment", false, "GROK_AUTH overrides file-based account switching")
	} else {
		add("environment", true, "no inline GROK_AUTH override")
	}

	list, listErr := application.List()
	if listErr != nil {
		add("registry", false, listErr.Error())
	} else {
		add("registry", true, fmt.Sprintf("%d saved account(s)", len(list.Registry.Accounts)))
		for _, account := range list.Registry.Accounts {
			data, snapshotErr := application.Store.ReadSnapshot(account.ID)
			if snapshotErr != nil {
				add("snapshot:"+account.Alias, false, snapshotErr.Error())
				continue
			}
			parsed, parseErr := grokauth.Parse(data)
			ok := parseErr == nil && parsed.Identity.ID == account.ID
			message := "valid private auth snapshot"
			if parseErr != nil {
				message = parseErr.Error()
			} else if parsed.Identity.ID != account.ID {
				message = "snapshot identity does not match registry"
			}
			add("snapshot:"+account.Alias, ok, message)
		}
		if list.CurrentError != nil {
			add("active-auth", false, list.CurrentError.Error())
		} else if list.CurrentIdentity == nil {
			add("active-auth", true, "not signed in")
		} else {
			add("active-auth", true, "valid "+list.CurrentIdentity.AuthMode+" credential")
		}
	}

	allOK := true
	for _, check := range checks {
		allOK = allOK && check.OK
	}
	if opts.bools["json"] {
		if err := writeJSON(out, struct {
			OK     bool          `json:"ok"`
			Checks []doctorCheck `json:"checks"`
		}{allOK, checks}); err != nil {
			return err
		}
	} else {
		for _, check := range checks {
			mark := "OK"
			if !check.OK {
				mark = "FAIL"
			}
			fmt.Fprintf(out, "[%s] %s: %s\n", mark, check.Name, check.Message)
		}
	}
	if !allOK {
		return errors.New("doctor found one or more problems")
	}
	return nil
}

func parseOptions(args, valueFlags, boolFlags []string) (options, error) {
	allowedValues := map[string]bool{}
	allowedBools := map[string]bool{"help": true}
	for _, name := range valueFlags {
		allowedValues[name] = true
	}
	for _, name := range boolFlags {
		allowedBools[name] = true
	}
	result := options{values: map[string]string{}, bools: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			result.passthrough = append(result.passthrough, args[i+1:]...)
			break
		}
		if arg == "-h" || arg == "--help" {
			return result, errors.New("run 'grok-switch help' for command usage")
		}
		if !strings.HasPrefix(arg, "--") {
			result.positionals = append(result.positionals, arg)
			continue
		}
		nameValue := strings.TrimPrefix(arg, "--")
		name, value, hasValue := strings.Cut(nameValue, "=")
		if allowedBools[name] {
			if hasValue {
				parsed, err := strconv.ParseBool(value)
				if err != nil {
					return result, fmt.Errorf("invalid value for --%s: %q", name, value)
				}
				result.bools[name] = parsed
			} else {
				result.bools[name] = true
			}
			continue
		}
		if allowedValues[name] {
			if !hasValue {
				i++
				if i >= len(args) {
					return result, fmt.Errorf("--%s requires a value", name)
				}
				value = args[i]
			}
			result.values[name] = value
			continue
		}
		return result, fmt.Errorf("unknown option --%s", name)
	}
	return result, nil
}

func printAccounts(out io.Writer, reg *accounts.Registry, currentID string, quotas map[string]billing.Quota) {
	if len(reg.Accounts) == 0 {
		fmt.Fprintln(out, "No saved accounts. Use 'grok-switch login' or 'grok-switch save'.")
		return
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "\t#\tALIAS\tEMAIL\tTIER\tQUOTA LEFT\tRESETS AT")
	for i, account := range reg.Accounts {
		marker := " "
		if account.ID == currentID {
			marker = "*"
		}
		email := account.Email
		if email == "" {
			email = "-"
		}
		quota, ok := quotas[account.ID]
		tierDisplay := "unknown"
		quotaDisplay := "unknown"
		resetDisplay := "unknown"
		if ok {
			if tier := strings.TrimSpace(quota.Tier); tier != "" {
				tierDisplay = tier
			}
			quotaDisplay = formatQuota(quota.RemainingPercent)
			resetDisplay = formatResetTime(quota.ResetAt)
		}
		fmt.Fprintf(w, "%s\t%02d\t%s\t%s\t%s\t%s\t%s\n",
			marker, i+1, account.Alias, email, tierDisplay, quotaDisplay, resetDisplay)
	}
	_ = w.Flush()
}

func formatQuota(value *float64) string {
	if value == nil {
		return "unknown"
	}
	if math.Abs(*value-math.Round(*value)) < 0.05 {
		return fmt.Sprintf("%.0f%%", *value)
	}
	return fmt.Sprintf("%.1f%%", *value)
}

func formatResetTime(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	resetAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "unknown"
	}
	return resetAt.In(time.Local).Format("01-02 15:04")
}

func promptSelection(in io.Reader, out io.Writer, count int) (string, error) {
	fmt.Fprintf(out, "Select account [1-%d, q to cancel]: ", count)
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if strings.EqualFold(value, "q") || value == "" {
		return "", errors.New("selection cancelled")
	}
	row, err := strconv.Atoi(value)
	if err != nil || row < 1 || row > count {
		return "", fmt.Errorf("invalid selection %q", value)
	}
	return strconv.Itoa(row), nil
}

func emailSuffix(email string) string {
	if email == "" {
		return ""
	}
	return " (" + email + ")"
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func fail(errOut io.Writer, err error) int {
	fmt.Fprintf(errOut, "Error: %v\n", err)
	return 1
}
