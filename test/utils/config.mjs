/**
 * Initialize the helper with defaults if nothing is provided
 * @param {object} baseUrl - Keycloak server URL
 * @param {object} username - Username to any user with credentials to create realms
 * @param {object} password - password
 */

const settings = {
  baseUrl: 'http://127.0.0.1:8080',
  realmName: 'master',
  username: 'admin',
  password: 'admin',
  grantType: 'password',
  clientId: 'admin-cli'
}

export default settings
