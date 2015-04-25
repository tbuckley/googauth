package googauth

import (
	"github.com/gorilla/sessions"
	"net/http"
)

const (
	kUserID              = "user_id"
	kAuthCodeTokenPrefix = "auth_token_"
)

// SessionManager lets you quickly retrieve data for the user's session
type SessionManager struct {
	store *sessions.CookieStore
	name  string
}

// Session wraps sessions.Session
type Session struct {
	session *sessions.Session
}

func NewSessionManager(secret []byte, name string) *SessionManager {
	m := new(SessionManager)
	m.store = sessions.NewCookieStore(secret)
	m.name = name
	return m
}

func (m *SessionManager) Get(r *http.Request) (*Session, error) {
	session, err := m.store.Get(r, m.name)
	if err != nil {
		return nil, err
	}

	s := new(Session)
	s.session = session
	return s, nil
}

func (m *SessionManager) WithSession(w http.ResponseWriter, r *http.Request, fn func(session *Session)) {
	session, err := m.Get(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fn(session)
}

func (s *Session) SetUserID(userID string) {
	s.session.Values[kUserID] = userID
}

func (s *Session) GetUserID() (string, bool) {
	user_id, ok := s.session.Values[kUserID].(string)
	return user_id, ok
}

func (s *Session) SetAuthCodeToken(token string, scope string) {
	s.session.Values[kAuthCodeTokenPrefix+scope] = token
}

func (s *Session) GetAuthCodeToken(scope string) (string, bool) {
	token, ok := s.session.Values[kAuthCodeTokenPrefix+scope].(string)
	return token, ok
}

func (s *Session) ClearUserID() {
	delete(s.session.Values, kUserID)
}

func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
	return s.session.Save(r, w)
}
