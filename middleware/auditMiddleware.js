const pool = require('../db');

// AUDIT MIDDLEWARE
const auditLog = async (req, res, next) => {
  if (!req.path.startsWith('/api/')) {
    return next();
  }
  const llmRoutePattern = /^\/api\/user\/(guardian\/)?(llm-ask-question|photo-upload|conversation\/.*|:?conversationId\/.*)/;

  if (llmRoutePattern.test(req.path)) {
    return next();
  }

  const originalSend = res.send;
  res.send = function (body) {
    const requestBody = { ...req.body };
    if (requestBody.password) {
      requestBody.password = '[REDACTED]';
    }
    if (requestBody.codeValue) {
      requestBody.codeValue = '[REDACTED]';
    }

    const logData = {
      changed_by: req.user ? req.user.user_id : null,
      endpoint: req.originalUrl,
      method: req.method,
      request_body: JSON.stringify(requestBody),
      response_status: res.statusCode
    };

    pool.execute(
      'INSERT INTO CSB.AUDIT_TRAIL (changed_by, endpoint, method, request_body, response_status) VALUES (?, ?, ?, ?, ?)',
      [logData.changed_by, logData.endpoint, logData.method, logData.request_body, logData.response_status]
    );

    originalSend.apply(res, arguments);
  };

  next();
};

module.exports = { auditLog };