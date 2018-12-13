/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

type RefreshTokenGrantHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	TokenRevocationStorage TokenRevocationStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan defines the lifetime of a refresh token.
	RefreshTokenLifespan time.Duration

	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token".
	if !request.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"refresh_token\"."))
	}

	refresh := request.GetRequestForm().Get("refresh_token")
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(refresh)
	realToken, _ := getPersistRefreshToken(refresh)

	originalRequest, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, request.GetSession())
	if errors.Cause(err) == fosite.ErrNotFound {
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug(err.Error()))
	} else if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	} else if err := c.RefreshTokenStrategy.ValidateRefreshToken(ctx, originalRequest, realToken); err != nil {
		// The authorization server MUST ... validate the refresh token.
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug(err.Error()))
	}

	if !originalRequest.GetGrantedScopes().HasOneOf("offline", "offline_access") {
		return errors.WithStack(fosite.ErrScopeNotGranted.WithHint("The OAuth 2.0 Client was not granted scope \"offline\" or \"offline_access\" and may thus not perform the \"refresh_token\" authorization grant."))

	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if originalRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHint("The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance."))
	}

	request.SetSession(originalRequest.GetSession().Clone())
	request.SetRequestedScopes(originalRequest.GetRequestedScopes())
	request.SetRequestedAudience(originalRequest.GetRequestedAudience())

	for _, scope := range originalRequest.GetGrantedScopes() {
		if !c.ScopeStrategy(request.GetClient().GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope \"%s\".", scope))
		}
		request.GrantScope(scope)
	}

	if err := c.AudienceMatchingStrategy(request.GetClient().GetAudience(), originalRequest.GetGrantedAudience()); err != nil {
		return err
	}

	for _, audience := range originalRequest.GetGrantedAudience() {
		request.GrantAudience(audience)
	}

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan).Round(time.Second))
	if c.RefreshTokenLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second))
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	newSignature := ""
	refreshToken := requester.GetRequestForm().Get("refresh_token")
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(refreshToken)
	// TODO: the behavior extensions don't support for access token, it only work
	// for openid token, the access token should be revoked every request
	behavior := requester.GetRequestForm().Get("behavior")

	// if refresh_token is not persisted, need to grant new refresh_token
	_, persist := getPersistRefreshToken(refreshToken)
	if !persist {
		refreshToken, newSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
		if strings.EqualFold(behavior, behaviorPersist) {
			newSignature = toPersistRefreshToken(newSignature)
			refreshToken = toPersistRefreshToken(refreshToken)
		}
	}

	ts, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	} else if err := c.TokenRevocationStorage.RevokeAccessToken(ctx, ts.GetID()); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	// Use persisted refresh_token to exchange access token, it should not be grant
	// new fresh_token, if granted new refresh_token, it should to revoke old one.
	// but if the behavior is derive new one, should don't revoke old one
	if len(newSignature) > 0 && !strings.EqualFold(behavior, behaviorDerive) {
		if err = c.TokenRevocationStorage.RevokeRefreshToken(ctx, ts.GetID()); err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
	}

	storeReq := requester.Sanitize([]string{})
	requestID := ts.GetID()
	// if derived a new refresh_token, the old on not be revoke, so the id is duplicated
	if strings.EqualFold(behavior, behaviorDerive) {
		if requestID, err = incrementString(requestID, deriveValue); err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
	}
	storeReq.SetID(requestID)
	if err := c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, storeReq); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}
	// if granted new refresh_token, should save it to db
	if len(newSignature) > 0 {
		if err := c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, newSignature, storeReq); err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, c.AccessTokenLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)
	return nil
}

var (
	persistValue    = "-persist"
	deriveValue     = "-"
	behaviorPersist = "persist"
	behaviorDerive  = "derive"
)

func getPersistRefreshToken(token string) (string, bool) {
	if strings.HasSuffix(token, persistValue) {
		return token[0 : len(token)-len(persistValue)], true
	}
	return token, false
}

func toPersistRefreshToken(token string) string {
	return strings.Join([]string{token, persistValue}, "")
}
func incrementString(str string, separator string) (string, error) {
	// set default values
	if separator == "" {
		separator = "_"
	}
	start := time.Date(2018, 12, 1, 0, 0, 0, 0, time.UTC)
	d := time.Now().Sub(start)
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(d.Seconds()))
	diff := base64.RawURLEncoding.EncodeToString(bs)
	// test to see if str already has integer suffix(ends with _%s)
	test := strings.SplitN(str, separator, 2)
	if len(test) >= 2 {
		return test[0] + separator + diff, nil
	}
	return str + separator + diff, nil
}
