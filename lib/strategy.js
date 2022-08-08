var passport = require("passport-strategy"),
  url = require("url"),
  crypto = require("crypto"),
  jws = require("jws"),
  base64url = require("base64url"),
  util = require("util"),
  utils = require("./utils"),
  OAuth2 = require("oauth").OAuth2,
  path = require("path"),
  fs = require("fs"),
  Profile = require("./profile"),
  NullStore = require("./state/null"),
  NonceStore = require("./state/session"),
  StateStore = require("./state/store"),
  PKCEStateStore = require("./state/pkcesession"),
  AuthorizationError = require("./errors/authorizationerror"),
  TokenError = require("./errors/tokenerror"),
  InternalOAuthError = require("./errors/internaloautherror");

/**
 * Creates an instance of `CFUaaStrategy`.
 *
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *   - `issuer`            Issuer URL
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *   - `jwks`        Certificate to validate the RSA Signature of the ID_Token
 *
 * Examples:
 *
 *     passport.use(new CFUaaStrategy({
 *         issuer: 'https://www.example.com/oauth2/token'
 *         authorizationURL: 'https://www.example.com/oauth2/authorize',
 *         tokenURL: 'https://www.example.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *         jwks: ['ssl/publicKey1.pem','ssl/publicKey2.pem']
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function CFUaaStrategy(options, verify) {
  if (typeof options == "function") {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) {
    throw new TypeError("CFUaaStrategy requires a verify callback");
  }
  if (!options.issuer) {
    throw new TypeError("CFUaaStrategy requires a issuer option");
  }
  if (!options.authorizationURL) {
    throw new TypeError("CFUaaStrategy requires a authorizationURL option");
  }
  if (!options.tokenURL) {
    throw new TypeError("CFUaaStrategy requires a tokenURL option");
  }
  if (!options.clientID) {
    throw new TypeError("CFUaaStrategy requires a clientID option");
  }
  if (!options.clientSecret) {
    throw new TypeError("CFUaaStrategy requires a clientSecret option");
  }

  if (!options.jwks && !options.jwksUri)
    throw new Error("CFUaaStrategy requires a jwks or jwksUri option");

  passport.Strategy.call(this);
  this.name = "cfuaa";
  this._verify = verify;

  this._authorizationURL = options.authorizationURL;
  this._tokenURL = options.tokenURL;
  this._userInfoURL = options.userInfoURL;
  this._issuer = options.issuer;

  this._clientID = options.clientID;
  this._clientSecret = options.clientSecret;
  this._callbackURL = options.callbackURL;
  this._userProfileURL = options.userProfileURL;

  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || " ";
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile =
    options.skipUserProfile === undefined ? false : options.skipUserProfile;

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(
    this._clientID,
    this._clientSecret,
    "",
    this._authorizationURL,
    this._tokenURL,
    options.customHeaders
  );

  //this._callbackURL = options.callbackURL;
  //this._scope = options.scope;
  //this._scopeSeparator = options.scopeSeparator || " ";
  this._pkceMethod = options.pkce === true ? "S256" : options.pkce;
  this._key =
    options.sessionKey ||
    "oauth2:" + url.parse(options.authorizationURL).hostname;

  if (options.store && typeof options.store == "object") {
    this._stateStore = options.store;
  } else if (options.store) {
    this._stateStore = options.pkce
      ? new PKCEStateStore({ key: this._key })
      : new StateStore({ key: this._key });
  } else if (options.state) {
    this._stateStore = options.pkce
      ? new PKCEStateStore({ key: this._key })
      : new NonceStore({ key: this._key });
  } else {
    if (options.pkce) {
      throw new TypeError(
        "CFUaaStrategy requires `state: true` option when PKCE is enabled"
      );
    }
    this._stateStore = new NullStore();
  }
  this._trustProxy = options.proxy;
  //this._passReqToCallback = options.passReqToCallback;
  //this._skipUserProfile =
  //  options.skipUserProfile === undefined ? false : options.skipUserProfile;
  //this._userProfileURL = options.userProfileURL;
  //this._issuer = options.issuer;
  this._oauth2.useAuthorizationHeaderforGET(true);

  this._HSAlg = ["HS256", "HS384", "HS512"];
  this._RSAlg = ["RS256", "RS384", "RS512"];
  this._ESAlg = ["ES256", "ES384", "ES512"];

  this._certs = [];
  if (options.jwks) {
    if (!util.isArray(options.jwks))
      throw new Error(
        "Please set the PublicKeys cert path list to be in an array format."
      );
    for (var i = 0; i < options.jwks.length; i++) {
      var filepath = options.jwks[i];

      if (filepath[0] === "/") var root = "/";
      else var root = "";

      var pathlist = filepath.split(/\//g);
      pathlist.unshift(root);

      filepath = path.join.apply(null, pathlist);

      var content = fs.readFileSync(filepath);
      this._certs.push(content);
    }
  } else {
    this._oauth2._request(
      "GET",
      options.jwksUri,
      null,
      null,
      null,
      (err, data) => {
        if (err) throw new TypeError("Failed to get JWKS");
        var _jwks = JSON.parse(data).keys;
        for (var i = 0; i < _jwks.length; i++) {
          this._certs.push(_jwks[i].value);
          //console.log(_jwks[i].value);
        }
      }
    );
  }
}

// Inherit from `passport.Strategy`.
util.inherits(CFUaaStrategy, passport.Strategy);

/**
 * Verify the Issuer Identifier in the ID Token
 *
 * @param {Object} jwtClaims
 * @return boolean
 */
CFUaaStrategy.prototype.verifyIssuer = function (jwtClaims) {
  return this._issuer === jwtClaims.iss;
};

/**
 * Verify the Authorized Party in the ID Token
 * Need to check that the Authorized Party property exists first
 * before calling this function
 *
 * @param {Object} jwtClaims
 * @return boolean
 */
CFUaaStrategy.prototype.verifyAzp = function (jwtClaims) {
  return this._clientID === jwtClaims.azp;
};

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
CFUaaStrategy.prototype.authenticate = function (req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    if (req.query.error == "access_denied") {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(
        new AuthorizationError(
          req.query.error_description,
          req.query.error,
          req.query.error_uri
        )
      );
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(
        utils.originalURL(req, { proxy: this._trustProxy }),
        callbackURL
      );
    }
  }

  var meta = {
    authorizationURL: this._oauth2._authorizeUrl,
    tokenURL: this._oauth2._accessTokenUrl,
    clientID: this._oauth2._clientId,
    callbackURL: callbackURL,
  };

  if (req.query && req.query.code) {
    function loaded(err, ok, state) {
      if (err) {
        return self.error(err);
      }
      if (!ok) {
        return self.fail(state, 403);
      }

      var code = req.query.code;

      var params = self.tokenParams(options);
      params.grant_type = "authorization_code";
      if (callbackURL) {
        params.redirect_uri = callbackURL;
      }
      if (typeof ok == "string") {
        // PKCE
        params.code_verifier = ok;
      }

      self._oauth2.getOAuthAccessToken(
        code,
        params,
        function (err, accessToken, refreshToken, params) {
          if (err) {
            return self.error(
              self._createOAuthError("Failed to obtain access token", err)
            );
          }
          if (!accessToken) {
            return self.error(new Error("Failed to obtain access token"));
          }

          // custom code extension
          var idToken = params["id_token"];
          if (!idToken) {
            return self.error(
              self.returnError("ID Token not present in token response")
            );
          }

          var idTokenSegments = idToken.split("."),
            jwtClaimsStr,
            jwtClaims,
            idHeader;

          try {
            idHeader = JSON.parse(new Buffer(idTokenSegments[0], "base64"));
            jwtClaimsStr = new Buffer(idTokenSegments[1], "base64").toString();
            jwtClaims = JSON.parse(jwtClaimsStr);
          } catch (ex) {
            return self.error(ex);
          }

          var iss = jwtClaims.iss;
          var sub = jwtClaims.sub;
          // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
          // "sub" claim was named "user_id".  Many providers still issue the
          // claim under the old field, so fallback to that.
          if (!sub) {
            sub = jwtClaims.user_id;
          }

          if (idHeader.alg) {
            if (self._HSAlg.indexOf(idHeader.alg) > -1) {
              if (
                !Array.isArray(jwtClaims.aud) ||
                (Array.isArray(jwtClaims.aud) && jwtClaims.aud.length === 1)
              ) {
                if (
                  !jwtClaims.azp ||
                  (jwtClaims.azp && jwtClaims.azp === jwtClaims.aud) ||
                  (jwtClaims.azp && jwtClaims.azp === jwtClaims.aud[0])
                ) {
                  var isValid = jws.verify(
                    idToken,
                    idHeader.alg,
                    self._clientSecret
                  );

                  if (!isValid) {
                    return self.error(
                      self.returnError("Token is invalid. Validation failed.")
                    );
                  }
                } else
                  return self.error(
                    self.returnError(
                      "Token is invalid. Authorized Party does not match with Audience."
                    )
                  );
              } else
                return self.error(
                  self.returnError("Token is invalid. Invalid Audience.")
                );
            } else if (
              self._RSAlg.indexOf(idHeader.alg) > -1 ||
              self._ESAlg.indexOf(idHeader.alg) > -1
            ) {
              var isValid = false;

              if (self._certs === null || self._certs.length === 0) {
                return self.error(
                  self.returnError(
                    "Certificate(s) are not provided. Validation failed."
                  )
                );
              }

              for (var i = 0; i < self._certs.length; i++) {
                if (jws.verify(idToken, idHeader.alg, self._certs[i]))
                  isValid = true;
              }

              if (!isValid) {
                return self.error(self.returnError("Invalid certificate(s)."));
              }
            } else return self.error(self.returnError("Invalid algorithm."));
          }

          if (
            !iss ||
            !sub ||
            !jwtClaims.aud ||
            !jwtClaims.exp ||
            !jwtClaims.iat
          ) {
            return self.error(self.returnError("Missing required claim(s)."));
          }

          // Verifying Issuer
          if (!self.verifyIssuer(jwtClaims)) {
            console.log(jwtClaims);
            return self.error(self.returnError("Mismatched Issuer."));
          }

          // Verifying Authorized Party (AZP)
          if (jwtClaims.azp) {
            if (!self.verifyAzp(jwtClaims)) {
              return self.error(
                self.returnError("Mismatched Authorized Party.")
              );
            }
          }

          // Verifying the Audience (AUD)
          if (Array.isArray(jwtClaims.aud)) {
            var audLength = jwtClaims.aud.length;
            if (audLength === 0) {
              return self.error(self.returnError("Audience is empty."));
            } else if (audLength > 1) {
              if (jwtClaims.azp) {
                // TODO: Need to check if array contains client ID. If not, reject.
                // Also need to check if there's any untrusted audiences. If so, reject.
                // As of now, client only trusts itself as an audience and nothing else.
                // This is due to each login having only one client, and thus only one audience.

                return self.error(
                  self.returnError("Audience may not have more than one entry.")
                );
              } else {
                return self.error(
                  self.returnError("Authorized Party is required.")
                );
              }
            } else {
              if (self._clientID !== jwtClaims.aud[0]) {
                return self.error(self.returnError("Mismatched Client Id."));
              }
            }
          } else {
            if (self._clientID !== jwtClaims.aud) {
              return self.error(self.returnError("Mismatched Client Id."));
            }
          }

          // Verifying Expired Time (EXP) time
          var currTime = Math.round(new Date().getTime() / 1000.0);
          if (currTime >= jwtClaims.exp) {
            return self.error(
              self.returnError(
                "Current time (" +
                  currTime +
                  ") is past ID Token Expired Time Claim (" +
                  jwtClaims.exp +
                  ")."
              )
            );
          }

          // end custom code extension

          self._loadUserProfile(accessToken, function (err, profile) {
            if (err) {
              return self.error(err);
            }

            function verified(err, user, info) {
              if (err) {
                return self.error(err);
              }
              if (!user) {
                return self.fail(info);
              }

              info = info || {};
              if (state) {
                info.state = state;
              }
              self.success(user, info);
            }

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(
                    req,
                    accessToken,
                    refreshToken,
                    params,
                    profile,
                    verified
                  );
                } else {
                  // arity == 5
                  self._verify(
                    req,
                    accessToken,
                    refreshToken,
                    profile,
                    verified
                  );
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(
                    accessToken,
                    refreshToken,
                    params,
                    profile,
                    verified
                  );
                } else {
                  // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    }

    var state = req.query.state;
    try {
      var arity = this._stateStore.verify.length;
      if (arity == 4) {
        this._stateStore.verify(req, state, meta, loaded);
      } else {
        // arity == 3
        this._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return this.error(ex);
    }
  } else {
    var params = this.authorizationParams(options);
    params.response_type = "code";
    if (callbackURL) {
      params.redirect_uri = callbackURL;
    }
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) {
        scope = scope.join(this._scopeSeparator);
      }
      params.scope = scope;
    }
    var verifier, challenge;

    if (this._pkceMethod) {
      verifier = base64url(crypto.pseudoRandomBytes(32));
      switch (this._pkceMethod) {
        case "plain":
          challenge = verifier;
          break;
        case "S256":
          challenge = base64url(
            crypto.createHash("sha256").update(verifier).digest()
          );
          break;
        default:
          return this.error(
            new Error(
              "Unsupported code verifier transformation method: " +
                this._pkceMethod
            )
          );
      }

      params.code_challenge = challenge;
      params.code_challenge_method = this._pkceMethod;
    }

    var state = options.state;
    if (state && typeof state == "string") {
      // NOTE: In passport-oauth2@1.5.0 and earlier, `state` could be passed as
      //       an object.  However, it would result in an empty string being
      //       serialized as the value of the query parameter by `url.format()`,
      //       effectively ignoring the option.  This implies that `state` was
      //       only functional when passed as a string value.
      //
      //       This fact is taken advantage of here to fall into the `else`
      //       branch below when `state` is passed as an object.  In that case
      //       the state will be automatically managed and persisted by the
      //       state store.
      params.state = state;

      var parsed = url.parse(this._oauth2._authorizeUrl, true);
      utils.merge(parsed.query, params);
      parsed.query["client_id"] = this._oauth2._clientId;
      delete parsed.search;
      var location = url.format(parsed);
      this.redirect(location);
    } else {
      function stored(err, state) {
        if (err) {
          return self.error(err);
        }

        if (state) {
          params.state = state;
        }
        var parsed = url.parse(self._oauth2._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query["client_id"] = self._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        self.redirect(location);
      }

      try {
        var arity = this._stateStore.store.length;
        if (arity == 5) {
          this._stateStore.store(req, verifier, state, meta, stored);
        } else if (arity == 4) {
          this._stateStore.store(req, state, meta, stored);
        } else if (arity == 3) {
          this._stateStore.store(req, meta, stored);
        } else {
          // arity == 2
          this._stateStore.store(req, stored);
        }
      } catch (ex) {
        return this.error(ex);
      }
    }
  }
};

/**
 * Retrieve user profile from service provider.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to load the user's profile from the service provider.  This assists
 * applications (and users of those applications) in the initial registration
 * process by automatically submitting required information.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
CFUaaStrategy.prototype.userProfile = function (accessToken, done) {
  // var self = this
  this._oauth2.get(
    this._userProfileURL,
    accessToken,
    function (err, body, res) {
      var json;

      if (err) {
        if (err.data) {
          try {
            json = JSON.parse(err.data);
          } catch (_) {}
        }

        // if (json && json.message) {
        //   return done(new APIError(json.message))
        // }
        return done(
          new InternalOAuthError("Failed to fetch user profile", err)
        );
      }

      try {
        json = JSON.parse(body);
      } catch (ex) {
        return done(new Error("Failed to parse user profile"));
      }

      var profile = Profile.parse(json);
      profile.provider = "cfuaa";
      profile._raw = body;
      profile._json = json;

      done(null, profile);
    }
  );
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
CFUaaStrategy.prototype.authorizationParams = function (options) {
  if (this._stateParamCallback) {
    return { state: this._stateParamCallback() };
  }
  return {};
};

/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
CFUaaStrategy.prototype.tokenParams = function (options) {
  return {};
};

/**
 * Parse error response from OAuth 2.0 endpoint.
 *
 * OAuth 2.0-based authentication strategies can overrride this function in
 * order to parse error responses received from the token endpoint, allowing the
 * most informative message to be displayed.
 *
 * If this function is not overridden, the body will be parsed in accordance
 * with RFC 6749, section 5.2.
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
CFUaaStrategy.prototype.parseErrorResponse = function (body, status) {
  var json = JSON.parse(body);
  if (json.error) {
    return new TokenError(json.error_description, json.error, json.error_uri);
  }
  return null;
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
CFUaaStrategy.prototype._loadUserProfile = function (accessToken, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }

  if (
    typeof this._skipUserProfile == "function" &&
    this._skipUserProfile.length > 1
  ) {
    // async
    this._skipUserProfile(accessToken, function (err, skip) {
      if (err) {
        return done(err);
      }
      if (!skip) {
        return loadIt();
      }
      return skipIt();
    });
  } else {
    var skip =
      typeof this._skipUserProfile == "function"
        ? this._skipUserProfile()
        : this._skipUserProfile;
    if (!skip) {
      return loadIt();
    }
    return skipIt();
  }
};

/**
 * Create an OAuth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
CFUaaStrategy.prototype._createOAuthError = function (message, err) {
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {}
  }
  if (!e) {
    e = new InternalOAuthError(message, err);
  }
  return e;
};

CFUaaStrategy.prototype.returnError = function (ErrMessage) {
  var ErrorObject = new Error(ErrMessage);
  Error.captureStackTrace(ErrorObject, arguments.callee);
  console.error(ErrorObject.stack);

  Error.stackTraceLimit = 0;
  ErrorObject = new Error(ErrMessage);
  Error.stackTraceLimit = 10;

  return ErrorObject;
};

CFUaaStrategy.prototype.returnInternalOAuthError = function (ErrMessage, err) {
  var ErrorObject = new InternalOAuthError(ErrMessage, err);
  Error.captureStackTrace(ErrorObject, arguments.callee);
  console.error(ErrorObject.stack);

  Error.stackTraceLimit = 0;
  ErrorObject = new InternalOAuthError(ErrMessage, err);
  Error.stackTraceLimit = 10;

  return ErrorObject;
};

// Expose constructor
module.exports = CFUaaStrategy;
