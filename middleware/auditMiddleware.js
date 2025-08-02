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
  res.send = async function (body) {
    originalSend.apply(res, arguments);

    const requestBody = { ...req.body };
    if (requestBody.password) {
      requestBody.password = '[REDACTED]';
    }
    if (requestBody.codeValue) {
      requestBody.codeValue = '[REDACTED]';
    }
    
    const getAction = (method, path) => {
        if (method === 'POST' && path === '/api/auth/login') return 'User Login';
        if (method === 'POST' && path === '/api/auth/signup') return 'User Registration';
        if (method === 'POST' && path === '/api/auth/verify-login') return 'OTP Verification';
        if (method === 'POST' && path === '/api/auth/forgot-password') return 'Forgot Password';
        if (method === 'POST' && path === '/api/auth/reset-password') return 'Reset Password';
        if (method === 'POST' && path === '/api/auth/resend-otp') return 'Resend OTP';
        return 'General';
    };

    const getStatus = (statusCode) => {
      return statusCode >= 200 && statusCode < 300 ? 'SUCCESS' : 'FAIL';
    };
    
    const logData = {
      changed_by: req.user ? req.user.user_id : null,
      action: getAction(req.method, req.path),
      status: getStatus(res.statusCode),
      endpoint: req.originalUrl,
      method: req.method,
      request_body: JSON.stringify(requestBody),
      response_status: res.statusCode,
      ip_address: req.ip,
      user_agent: req.headers['user-agent']
    };

    try {
      await pool.execute(
        'INSERT INTO CSB.AUDIT_TRAIL (changed_by, action, status, endpoint, method, request_body, response_status, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [logData.changed_by, logData.action, logData.status, logData.endpoint, logData.method, logData.request_body, logData.response_status, logData.ip_address, logData.user_agent]
      );
    } catch (error) {
        if (error.code === 'ER_DATA_TOO_LONG') {
            const truncatedBody = logData.request_body.substring(0, 2000);
            pool.execute(
                'INSERT INTO CSB.AUDIT_TRAIL (changed_by, action, status, endpoint, method, request_body, response_status, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [logData.changed_by, logData.action, logData.status, logData.endpoint, logData.method, truncatedBody, logData.response_status, logData.ip_address, logData.user_agent]
            ).catch(err => {
                console.error('Audit trail fallback insert failed:', err);
            });
        } else {
            console.error('Audit trail error:', error);
        }
    }
  };

  next();
};

module.exports = { auditLog };