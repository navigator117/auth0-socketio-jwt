const xtend             = require('xtend');
const jwt               = require('jsonwebtoken');
const UnauthorizedError = require('./UnauthorizedError');

function authorize (options) {
  options = xtend({ decodedPropertyName: 'decoded_token', encodedPropertyName: 'encoded_token' }, options);

  if (typeof options.secret !== 'string' && typeof options.secret !== 'function') {
    throw new Error(`Provided secret ${options.secret} is invalid, must be of type string or function.`);
  }

  const defaults = {
    success: function(socket, accept) {
      if (socket.request) {
        accept();
      } else {
        accept(null, true);
      }
    },
     fail: function(error, socket, accept) {
      if (socket.request) {
        accept(error);
      } else {
        accept(null, false);
      }
    }
  };

  const auth = xtend(defaults, options);

  return function(packet, accept) {
    'use strict'; // Node 4.x workaround
    let token, error;
    let socket = this;
    const handshake = socket.handshake;
    const req = socket.request;

    if (handshake && handshake.query.token) {
      token = handshake.query.token;
    }
    else if (req._query && req._query.token) {
      token = req._query.token;
    }
    else if (req.query && req.query.token) {
      token = req.query.token;
    }

   if (!token) {
      error = new UnauthorizedError('credentials_required', {
        message: 'no token provided'
      });
      return auth.fail(error, socket, accept);
    }

    // Store encoded JWT
    socket[options.encodedPropertyName] = token;

    const onJwtVerificationReady = (err, decoded) => {
      if (err) {
        error = new UnauthorizedError(err.code || 'invalid_token', err);
        return auth.fail(error, socket, accept);
      }

      socket[options.decodedPropertyName] = options.customDecoded
        ? options.customDecoded(decoded)
        : decoded;

	if (options.anotherLogin) {
	    let anotherLoginUser = options.anotherLogin(socket[options.decodedPropertyName]);
	    if (anotherLoginUser) {
		error = new UnauthorizedError('another_login', {
		    message: anotherLoginUser
		});
		return auth.fail(error, socket, accept);
	    }		
	}
      return auth.success(socket, accept);
    };

    const onSecretReady = (err, secret) => {
      if (err) {
        error = new UnauthorizedError(err.code || 'invalid_secret', err);
        return auth.fail(error, socket, accept);
      }

      jwt.verify(token, secret, options, onJwtVerificationReady);
    };

    getSecret(req, options.secret, token, onSecretReady);
  };
}

function getSecret (request, secret, token, callback) {
  'use strict'; // Node 4.x workaround

  if (typeof secret === 'function') {
    if (!token) {
      return callback({ code: 'invalid_token', message: 'jwt must be provided' });
    }

    const parts = token.split('.');

    if (parts.length < 3) {
      return callback({ code: 'invalid_token', message: 'jwt malformed' });
    }

    if (parts[2].trim() === '') {
      return callback({ code: 'invalid_token', message: 'jwt signature is required' });
    }

    let decodedToken = jwt.decode(token, { complete: true });

    if (!decodedToken) {
      return callback({ code: 'invalid_token', message: 'jwt malformed' });
    }

    const arity = secret.length;
    if (arity == 4) {
      secret(request, decodedToken.header, decodedToken.payload, callback);
    } else { // arity == 3
      secret(request, decodedToken.payload, callback);
    }
  } else {
    callback(null, secret);
  }
}

exports.authorize = authorize;
exports.UnauthorizedError = UnauthorizedError;
