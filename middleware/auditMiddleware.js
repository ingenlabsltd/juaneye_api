const pool = require('../db');

// AUDIT MIDDLEWARE
const auditLog = async (req, res, next) => {
  const excludedRoutes = [
    '/user/guardian/llm-ask-question',
    '/user/llm-ask-question'
  ];

  if (excludedRoutes.includes(req.path)) {
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