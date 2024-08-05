// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See [LICENSE.txt] for license information.
// [LICENSE.txt]: https://github.com/mattermost/mattermost/blob/03a5b4a288ba60c52e604e5ef017cf5fc179db51/LICENSE.txt

package oauthopenid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"

	"github.com/mattermost/mattermost/server/v8/channels/app"
)

type CacheData struct {
	Service  string
	Expires  int64
	Settings model.SSOSettings
}

type OpenIdMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserEndpoint          string   `json:"userinfo_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	Algorithms            []string `json:"id_token_signing_alg_values_supported"`
}

type OpenIdProvider struct {
	CacheData *CacheData
	userService app.UserService
}

type OpenIdUser struct {
	Id        string `json:"sub"`
	Oid       string `json:"oid"` //Office 365 only
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
	Name      string `json:"name"`
	Nickname  string `json:"nickname"`
	Email     string `json:"email"`
}

func init() {
	provider := &OpenIdProvider{}
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, provider)
}

func (o *OpenIdProvider) userFromOpenIdUser(logger mlog.LoggerIFace, u *OpenIdUser) *model.User {
	user := &model.User{}

	user.Email = u.Email
	user.Username = model.CleanUsername(logger, strings.Split(user.Email, "@")[0])
	if o.CacheData.Service == model.ServiceGitlab && u.Nickname != "" {
		user.Username = u.Nickname
	}

	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.Nickname = u.Nickname

	user.AuthData = new(string)
	*user.AuthData = o.getAuthData(u)

	return user
}

func (o *OpenIdProvider) getAuthData(u *OpenIdUser) string {
	if o.CacheData.Service == model.ServiceOffice365 {
		if u.Oid != "" {
			return u.Oid
		}
	}
	return u.Id
}

func openIDUserFromJSON(data io.Reader) (*OpenIdUser, error) {
	decoder := json.NewDecoder(data)
	var u OpenIdUser
	err := decoder.Decode(&u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (u *OpenIdUser) IsValid() error {
	if u.Id == "" {
		return errors.New("invalid id")
	}

	if u.Email == "" {
		return errors.New("invalid emails")
	}
	return nil
}

func (u *OpenIdUser) GetIdentifier() string {
	return model.ServiceOpenid
}

func (o *OpenIdProvider) GetUserFromJSON(c request.CTX, data io.Reader, tokenUser *model.User) (*model.User, error) {
    oid, err := openIDUserFromJSON(data)
    if err != nil {
        return nil, fmt.Errorf("error parsing Keycloak user data: %w", err)
    }

    // Use the Keycloak user ID directly as the auth data
    authData := oid.Id
    
    // Try to find user by Keycloak ID first
    user, err := o.UserService.GetUserByAuth(c, authData, o.CacheData.Service)
    if err != nil && !model.IsErrNoRows(err) {
        return nil, fmt.Errorf("error checking for existing user by auth data: %w", err)
    }

    if user == nil {
        // If not found by Keycloak ID, try to find by email
        user, err = o.UserService.GetUserByEmail(c, oid.Email)
        if err != nil && !model.IsErrNoRows(err) {
            return nil, fmt.Errorf("error checking for existing user by email: %w", err)
        }
    }

    if user != nil {
        // User exists, update with Keycloak data
        if user.AuthService != o.CacheData.Service {
            c.Logger().Info("Linking existing Mattermost account to Keycloak", 
                mlog.String("user_id", user.Id),
                mlog.String("previous_auth_service", user.AuthService))
        }
        return o.updateUserWithKeycloakData(c, user, oid, authData)
    }

    // User doesn't exist, create new user
    return o.createUserFromKeycloakData(c, oid, authData)
}

func (o *OpenIdProvider) updateUserWithKeycloakData(c request.CTX, existingUser *model.User, oid *OpenIdUser, authData string) (*model.User, error) {
    previousEmail := existingUser.Email
    previousAuthService := existingUser.AuthService

    existingUser.FirstName = oid.FirstName
    existingUser.LastName = oid.LastName
    existingUser.Nickname = oid.Nickname
    existingUser.Email = oid.Email
    existingUser.EmailVerified = true
    existingUser.AuthData = &authData
    existingUser.AuthService = o.CacheData.Service

    updatedUser, err := o.UserService.UpdateUser(c, existingUser, false)
    if err != nil {
        return nil, fmt.Errorf("error updating existing user with Keycloak data: %w", err)
    }

    if previousEmail != oid.Email {
        c.Logger().Info("User email updated from Keycloak", 
            mlog.String("user_id", updatedUser.Id),
            mlog.String("previous_email", previousEmail),
            mlog.String("new_email", oid.Email))
    }

    if previousAuthService != o.CacheData.Service {
        c.Logger().Info("User auth service updated to Keycloak", 
            mlog.String("user_id", updatedUser.Id),
            mlog.String("previous_auth_service", previousAuthService))
    }

    return updatedUser, nil
}

func (o *OpenIdProvider) createUserFromKeycloakData(c request.CTX, oid *OpenIdUser, authData string) (*model.User, error) {
    newUser := &model.User{
        Email:         oid.Email,
        FirstName:     oid.FirstName,
        LastName:      oid.LastName,
        Nickname:      oid.Nickname,
        EmailVerified: true,
        AuthData:      &authData,
        AuthService:   o.CacheData.Service,
    }

    createdUser, err := o.UserService.CreateUser(c, newUser)
    if err != nil {
        return nil, fmt.Errorf("error creating new user from Keycloak data: %w", err)
    }

    c.Logger().Info("Created new Mattermost account from Keycloak", mlog.String("user_id", createdUser.Id))
    return createdUser, nil

}

func (o *OpenIdProvider) combineUsers(jsonUser *model.User, tokenUser *model.User) *model.User {
	if o.CacheData.Service == model.ServiceOffice365 {
		jsonUser.AuthData = tokenUser.AuthData
	}
	return jsonUser
}

func (o *OpenIdProvider) GetAuthDataFromJSON(data io.Reader) (string, error) {
	u, err := openIDUserFromJSON(data)
	if err != nil {
		return "", err
	}

	err = u.IsValid()
	if err != nil {
		return "", err
	}
	return o.getAuthData(u), nil
}

// GetSSOSettings returns SSO Settings from Cache or Discovery Document
func (o *OpenIdProvider) GetSSOSettings(_ request.CTX, config *model.Config, service string) (*model.SSOSettings, error) {
	settings := config.OpenIdSettings
	if service == model.ServiceOffice365 {
		settings = *config.Office365Settings.SSOSettings()
	} else if service == model.ServiceGoogle {
		settings = config.GoogleSettings
	} else if service == model.ServiceGitlab {
		settings = config.GitLabSettings
	}

	if o.CacheData != nil && !settingsChanged(*o.CacheData, service, settings) && o.CacheData.Expires > time.Now().Unix() {
		return &o.CacheData.Settings, nil
	}

	var age int64 = 0
	if *settings.DiscoveryEndpoint != "" {
		response, err := http.Get(*settings.DiscoveryEndpoint)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()

		for _, v := range strings.Split(response.Header.Get("Cache-Control"), ",") {
			if strings.Contains(v, "max-age") {
				ageValue := strings.Split(v, "=")[1]
				age, _ = strconv.ParseInt(ageValue, 10, 64)
			}
		}
		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}

		var openIDResponse OpenIdMetadata
		err = json.Unmarshal(responseData, &openIDResponse)
		if err != nil {
			return nil, err
		}

		settings.AuthEndpoint = &openIDResponse.AuthorizationEndpoint
		settings.TokenEndpoint = &openIDResponse.TokenEndpoint
		settings.UserAPIEndpoint = &openIDResponse.UserEndpoint
	}
	expires := time.Now().Unix() + age

	o.CacheData = &CacheData{
		Service:  service,
		Expires:  expires,
		Settings: settings,
	}
	return &settings, nil
}

func settingsChanged(cacheData CacheData, service string, configSettings model.SSOSettings) bool {
	if cacheData.Service == service &&
		cacheData.Settings.DiscoveryEndpoint == configSettings.DiscoveryEndpoint &&
		cacheData.Settings.Secret == configSettings.Secret &&
		cacheData.Settings.Id == configSettings.Id {
		return false
	}
	return true
}

func (o *OpenIdProvider) GetUserFromIdToken(c request.CTX, idToken string) (*model.User, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid Id Token")
	}

	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	claims := &OpenIdUser{}
	json.Unmarshal(b, &claims)

	return o.userFromOpenIdUser(c.Logger(), claims), nil
}

func (o *OpenIdProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	// Office365 OAuth would store Ids without dashes. (ie. 0e8fddd450d344999a93a390ee8cb83d)
	// Office365 OpenId will return as a formatted GUID (ie. '0e8fddd4-50d3-4499-9a93-a390ee8cb83d')
	// If this is a UUID that starts with all zero. (ie. 00000000-0000-0000-be95-fe607df5dbeb)
	// For backwards compatibility we store the auth data from OAuth as be95fe607df5dbeb
	if dbUser.AuthData == nil || oauthUser.AuthData == nil {
		return false
	}
	dbID := *dbUser.AuthData
	oauthID := *oauthUser.AuthData
	if dbID == "" || oauthID == "" {
		return false
	}
	parts := strings.Split(oauthID, "-")
	for _, part := range parts {
		if strings.Count(part, "0") != len(part) {
			if !strings.Contains(dbID, part) {
				return false
			}
		}
	}
	return true
}
