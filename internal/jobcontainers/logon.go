package jobcontainers

import (
	"fmt"
	"strings"

	"github.com/Microsoft/hcsshim/internal/winapi"
	"github.com/danieljoos/wincred"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
)

// processToken returns a user token for the user specified by `user`. This should be in the form
// of either a DOMAIN\username or just username.
func processToken(user string) (windows.Token, error) {
	var (
		domain   string
		userName string
		token    windows.Token
	)

	split := strings.Split(user, "\\")
	if len(split) == 2 {
		domain = split[0]
		userName = split[1]
	} else if len(split) == 1 {
		userName = split[0]
	} else {
		return 0, fmt.Errorf("invalid user string `%s`", user)
	}

	if user == "" {
		return 0, errors.New("empty user string passed")
	}

	var password *uint16 = nil
	logonType := winapi.LOGON32_LOGON_INTERACTIVE
	// User asking to run as a local system account (NETWORK SERVICE, LOCAL SERVICE, SYSTEM)
	if domain == "NT AUTHORITY" {
		logonType = winapi.LOGON32_LOGON_SERVICE
	} else if domain == "localhost" {
		cred, err := wincred.GetGenericCredential(user)
		if err != nil {
			return 0, fmt.Errorf("Error retrieving credentials for user `%s`", user)
		}

		decoder := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
		passwordString, err := decoder.String(string(cred.CredentialBlob))
		if err != nil {
			return 0, fmt.Errorf("Error decoding credential string for user `%s`", user)
		}

		password = windows.StringToUTF16Ptr(passwordString)
	}

	if err := winapi.LogonUser(
		windows.StringToUTF16Ptr(userName),
		windows.StringToUTF16Ptr(domain),
		password,
		logonType,
		winapi.LOGON32_PROVIDER_DEFAULT,
		&token,
	); err != nil {
		return 0, errors.Wrap(err, "failed to logon user")
	}
	return token, nil
}

func openCurrentProcessToken() (windows.Token, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &token); err != nil {
		return 0, errors.Wrap(err, "failed to open current process token")
	}
	return token, nil
}
