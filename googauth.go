package googauth

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/dustin/randbo"
	"github.com/tbuckley/apitools"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/appengine/urlfetch"
)

var (
	ErrSessionMissingAuthToken = errors.New("no auth code token set for session")
	ErrNotSignedIn             = errors.New("not signed in")
)

func GetConfig(clientID, clientSecret string, scopes []string, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}
}

func GenerateUniqueToken() (string, error) {
	// @TODO(tbuckley) use crypto/rand
	r := randbo.New()
	data := make([]byte, 16)
	_, err := r.Read(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func GenerateAuthURL(config *oauth2.Config) (url, token string, err error) {
	token, err = GenerateUniqueToken()
	if err != nil {
		return "", "", err
	}
	url = config.AuthCodeURL(token, oauth2.AccessTypeOffline)
	return url, token, nil
}

// AuthURLForSession will return the URL to let the user enter the oauth flow.
// A CSRF token will be stored in the user's session.
func AuthURLForSession(config *oauth2.Config, session *Session, scope string) (string, error) {
	url, token, err := GenerateAuthURL(config)
	if err != nil {
		return "", err
	}

	session.SetAuthCodeToken(token, scope)
	return url, nil
}

// ConfirmAuthTokenForSession will return true if the given token mathces the
// CSRF token stored in the user's session. See AuthURLForSession.
func ConfirmAuthTokenForSession(session *Session, token string, scope string) (bool, error) {
	trueToken, ok := session.GetAuthCodeToken(scope)
	if !ok {
		return true, ErrSessionMissingAuthToken
	}

	return (trueToken == token), nil
}

func TokenForCode(config *oauth2.Config, c context.Context, code string) (*oauth2.Token, error) {
	token, err := config.Exchange(c, code)
	return token, err
}

func ClientForToken(config *oauth2.Config, c context.Context, token *oauth2.Token) *http.Client {
	// return config.Client(c, token)
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: config.TokenSource(c, token),
			Base: &urlfetch.Transport{
				Context: c,
			},
		},
	}
}

type BasicTokenSource struct {
	token *oauth2.Token
}

func (s *BasicTokenSource) Token() (*oauth2.Token, error) {
	return s.token, nil
}

func ClientForAccessToken(c context.Context, accessToken string) *http.Client {
	token := &oauth2.Token{
		AccessToken: accessToken,
	}

	// return config.Client(c, token)
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: &BasicTokenSource{token},
			Base: &urlfetch.Transport{
				Context: c,
			},
		},
	}
}

type UserCredentials struct {
	AuthorizationCode string `json:"authorization_code"`
}

func TokenForLoginRequest(config *oauth2.Config, c context.Context, r *http.Request) (*oauth2.Token, error) {
	// Read the user's credentials
	credentials := new(UserCredentials)
	err := apitools.ReadJSON(r.Body, credentials)
	if err != nil {
		return nil, err
	}

	// Exchange the user's authorization code for an oauth token
	token, err := TokenForCode(config, c, credentials.AuthorizationCode)
	return token, err
}

func Login(sessionManager *SessionManager, userID string, r *http.Request, w http.ResponseWriter) {
	session, err := sessionManager.Get(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.SetUserID(userID)
	session.Save(r, w)
}

func Logout(sessionManager *SessionManager, r *http.Request, w http.ResponseWriter) {
	session, err := sessionManager.Get(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.ClearUserID()
	session.Save(r, w)
}

func GetSignedInUserID(sessionManager *SessionManager, r *http.Request) (string, error) {
	session, err := sessionManager.Get(r)
	if err != nil {
		return "", err
	}

	userID, ok := session.GetUserID()
	if !ok {
		return "", ErrNotSignedIn
	}

	return userID, nil
}

func Authenticated(sessionManager *SessionManager, w http.ResponseWriter, r *http.Request, fn func(userID string)) {
	userID, err := GetSignedInUserID(sessionManager, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fn(userID)
}

type LoginRedirecter struct {
	sessionManager *SessionManager
	urlStr         string
	handler        http.Handler
}

func (lr *LoginRedirecter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := GetSignedInUserID(lr.sessionManager, r)
	if err != nil {
		switch err {
		case ErrNotSignedIn:
			http.Redirect(w, r, lr.urlStr, http.StatusFound)
			return
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	lr.handler.ServeHTTP(w, r)
}

func LoginRedirect(sessionManager *SessionManager, urlStr string, handler http.Handler) http.Handler {
	return &LoginRedirecter{
		sessionManager: sessionManager,
		urlStr:         urlStr,
		handler:        handler,
	}
}
