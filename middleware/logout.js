/*
 * Copyright 2016 Red Hat Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
'use strict'

const URL = require('url')

module.exports = function (keycloak, logoutUrl) {
  const config = keycloak.getConfig();

  return function logout (request, response, next) {
    const requestUrl = request.originalUrl || request.url;

    const parsedRequest = URL.parse(requestUrl, true); // eslint-disable-line
    if (parsedRequest.pathname !== logoutUrl) {
      return next()
    }

    let idTokenHint = null
    if (request.kauth.grant) {
      idTokenHint = request.kauth.grant.id_token.token
      keycloak.deauthenticated(request, response)
      request.kauth.grant.unstore(request, response)
      delete request.kauth.grant
    }

    const queryParams = parsedRequest.query
    let redirectUrl = queryParams && queryParams.redirect_url

    // If we do not found redirect url in query parameter
    // We will use the configured one
    redirectUrl = config.app?.logout?.redirectUrl;

    if (!redirectUrl) {
      const host = request.hostname
      const headerHost = request.headers.host.split(':')
      const port = headerHost[1] || ''
      redirectUrl = request.protocol + '://' + host + (port === '' ? '' : ':' + port) + '/'
    }
    const keycloakLogoutUrl = keycloak.logoutUrl(redirectUrl, idTokenHint)

    response.redirect(keycloakLogoutUrl)
  }
}
