package fosite_test

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/handler/authorize/explicit"
	. "github.com/ory-am/fosite/internal"
	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	goauth2 "golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var clientID = "foo"
var clientSecret = "barbarbarbarbar"
var clientSecretByte = []byte("barbarbarbarbar")
var state = "random-state"
var ts *httptest.Server

var mockStore *MockStorage
var mockClient *MockClient
var mockAuthStore *MockAuthorizeStorage
var mockAuthReq *MockAuthorizeRequester

func TestFosite(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockStore = NewMockStorage(ctrl)
	mockClient = NewMockClient(ctrl)
	mockAuthStore = NewMockAuthorizeStorage(ctrl)
	mockAuthReq = NewMockAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	authExplicitHandler := &explicit.AuthorizeExplicitEndpointHandler{
		Enigma: &enigma.HMACSHAEnigma{GlobalSecret: []byte("super-global-secret")},
		Store:  mockAuthStore,
	}
	oauth2 := &Fosite{
		Store: mockStore,
		AuthorizeEndpointHandlers: AuthorizeEndpointHandlers{
			authExplicitHandler,
		},
		TokenEndpointHandlers: TokenEndpointHandlers{
			authExplicitHandler,
		},
	}

	oauth2TestAuthorizeCodeWorkFlow(oauth2, t, func() {
		mockStore = NewMockStorage(ctrl)
		mockAuthReq = NewMockAuthorizeRequester(ctrl)
		mockClient = NewMockClient(ctrl)
		mockAuthStore = NewMockAuthorizeStorage(ctrl)
		oauth2.Store = mockStore
		authExplicitHandler.Store = mockAuthStore
	})
}

func oauth2TestAuthorizeCodeWorkFlow(oauth2 OAuth2Provider, t *testing.T, refreshMocks func()) {
	const workingClientID = "foo"
	const workingClientSecret = "secretsecretsecretsecret"
	const state = "secure-random-state"

	var workingClientHashedSecret = []byte("$2a$10$rUQDYblu3fytMb9aQ3soh.yKNe.17spWcY9fUkkvI9Nv7U1NJCMV2")
	var session = &struct {
		UserID string
	}{
		UserID: "foo",
	}

	router := mux.NewRouter()
	router.HandleFunc("/auth", func(rw http.ResponseWriter, req *http.Request) {
		ctx := NewContext()

		ar, err := oauth2.NewAuthorizeRequest(ctx, req)
		if err != nil {
			t.Logf("Request %s failed because %s", ar, err)
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}

		// Normally, this would be the place where you would check if the user is logged in and gives his consent.
		// For this test, let's assume that the user exists, is logged in, and gives his consent...

		response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, session)
		if err != nil {
			t.Logf("Response %s failed because %s", ar, err)
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}

		oauth2.WriteAuthorizeResponse(rw, ar, response)
	})
	router.HandleFunc("/cb", func(rw http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		if q.Get("code") == "" && q.Get("error") == "" {
			assert.NotEmpty(t, q.Get("code"))
			assert.NotEmpty(t, q.Get("error"))
		}

		if q.Get("code") != "" {
			rw.Write([]byte("code: ok"))
		}
		if q.Get("error") != "" {
			rw.Write([]byte("error: " + q.Get("error")))
		}
	})
	router.HandleFunc("/token", func(rw http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		ctx := NewContext()
		var mySessionData struct {
			Foo string
		}

		accessRequest, err := oauth2.NewAccessRequest(ctx, req, &mySessionData)
		if err != nil {
			t.Logf("Access request %s failed because %s", accessRequest, err.Error())
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		response, err := oauth2.NewAccessResponse(ctx, req, accessRequest, &mySessionData)
		if err != nil {
			t.Logf("Access resonse %s failed because %s\n", accessRequest, err.Error())
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		oauth2.WriteAccessResponse(rw, accessRequest, response)
	})

	ts = httptest.NewServer(router)
	defer ts.Close()

	for k, c := range []struct {
		conf               goauth2.Config
		state              string
		expectBody         string
		expectStatusCode   int
		expectPath         string
		expectedTokenError bool
		mock               func()
	}{
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  ts.URL + "/cb",
				Endpoint: goauth2.Endpoint{
					AuthURL: ts.URL + "/auth",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(nil, errors.New("foo"))

				mockClient.EXPECT().CompareSecretWith(gomock.Any()).AnyTimes().Return(true)
				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})

				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, errors.New("foo"))
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/auth",
			expectBody:         "{\n\t\"name\": \"invalid_client\",\n\t\"description\": \"Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)\"\n}",
			expectedTokenError: true,
		},
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  ts.URL + "/cb",
				Endpoint: goauth2.Endpoint{
					AuthURL:  ts.URL + "/auth",
					TokenURL: ts.URL + "/token",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(mockClient, nil)
				mockClient.EXPECT().CompareSecretWith(gomock.Eq(clientSecretByte)).AnyTimes().Return(true)
				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})

				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().AnyTimes().Return(nil, errors.New("foo"))
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/cb",
			expectBody:         "error: invalid_scope",
			expectedTokenError: true,
		},
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Scopes:       []string{DefaultRequiredScopeName},
				RedirectURL:  ts.URL + "/cb",
				Endpoint: goauth2.Endpoint{
					AuthURL:  ts.URL + "/auth",
					TokenURL: ts.URL + "/token",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(mockClient, nil)
				mockClient.EXPECT().CompareSecretWith(gomock.Eq(clientSecretByte)).AnyTimes().Return(true)
				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})
				mockAuthStore.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().AnyTimes().Return(nil, errors.New("foo"))
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/cb",
			expectBody:         "code: ok",
			expectedTokenError: true,
		},
		{
			conf: goauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  ts.URL + "/cb",
				Scopes:       []string{DefaultRequiredScopeName},
				Endpoint: goauth2.Endpoint{
					AuthURL:  ts.URL + "/auth",
					TokenURL: ts.URL + "/token",
				},
			},
			state: state,
			mock: func() {
				mockStore.EXPECT().GetClient(gomock.Eq(clientID)).AnyTimes().Return(mockClient, nil)
				mockClient.EXPECT().GetID().AnyTimes().Return(clientID)
				mockClient.EXPECT().CompareSecretWith(gomock.Eq(clientSecretByte)).AnyTimes().Return(true)
				mockClient.EXPECT().GetHashedSecret().AnyTimes().Return(workingClientHashedSecret)
				mockClient.EXPECT().GetRedirectURIs().AnyTimes().Return([]string{ts.URL + "/cb"})

				mockAuthStore.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)

				mockAuthStore.EXPECT().GetAuthorizeCodeSession(gomock.Any(), gomock.Any()).AnyTimes().Return(mockAuthReq, nil)
				mockAuthStore.EXPECT().CreateAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockAuthStore.EXPECT().CreateRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
				mockAuthStore.EXPECT().DeleteAuthorizeCodeSession(gomock.Any()).AnyTimes().Return(nil)
				mockAuthReq.EXPECT().GetClient().AnyTimes().Return(mockClient)
				mockAuthReq.EXPECT().GetRequestedAt().AnyTimes().Return(time.Now())
				mockAuthReq.EXPECT().GetScopes().Return([]string{DefaultRequiredScopeName})
			},
			expectStatusCode:   http.StatusOK,
			expectPath:         "/cb",
			expectBody:         "code: ok",
			expectedTokenError: false,
		},

		// TODO add a ton of tests for RFC conform tests. use factories! See https://github.com/ory-am/fosite/issues/13
	} {
		refreshMocks()
		c.mock()
		authurl := c.conf.AuthCodeURL(c.state)
		req := gorequest.New()
		resp, body, errs := req.Get(authurl).End()
		require.Len(t, errs, 0, "%s", errs)
		assert.Equal(t, c.expectPath, resp.Request.URL.Path)
		assert.Equal(t, c.expectBody, body)
		assert.Equal(t, c.expectStatusCode, resp.StatusCode)

		authorizeCode := resp.Request.URL.Query().Get("code")
		token, err := c.conf.Exchange(context.Background(), authorizeCode)
		assert.Equal(t, c.expectedTokenError, err != nil, "%d: %s", k, err)
		if !c.expectedTokenError {
			assert.NotNil(t, token)
		}
		t.Logf("Got token %s", token)
		t.Logf("Passed test case %d", k)
	}
}
