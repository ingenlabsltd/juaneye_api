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
        // Auth Routes
        if (method === 'POST' && path === '/api/auth/signup') return 'User Registration';
        if (method === 'POST' && path === '/api/auth/login') return 'User Login';
        if (method === 'POST' && path === '/api/auth/forgot-password') return 'Forgot Password';
        if (method === 'POST' && path === '/api/auth/reset-password') return 'Reset Password';
        if (method === 'POST' && path === '/api/auth/verify-login') return 'OTP Verification';
        if (method === 'POST' && path === '/api/auth/resend-otp') return 'Resend OTP';

        // User Routes
        if (method === 'GET' && path === '/api/user/dashboard') return 'Get User Dashboard';
        if (method === 'GET' && path === '/api/user/profile') return 'Get User Profile';
        if (method === 'POST' && path === '/api/user/ocr-scans') return 'Create OCR Scan';
        if (method === 'POST' && path === '/api/user/object-scans') return 'Create Object Scan';
        if (method === 'GET' && path === '/api/user/scans') return 'Get User Scans';
        if (method === 'GET' && path.match(/^\/api\/user\/scans\/\w+$/)) return 'Get Single Scan';
        if (method === 'PUT' && path.match(/^\/api\/user\/scans\/\w+$/)) return 'Update Scan';
        if (method === 'DELETE' && path.match(/^\/api\/user\/scans\/\w+$/)) return 'Delete Scan';
        if (method === 'POST' && path === '/api/user/photo-upload') return 'Upload Photo';
        if (method === 'POST' && path === '/api/user/llm-ask-question') return 'Ask LLM';
        if (method === 'GET' && path === '/api/user/get-guardians') return 'Get User Guardians';
        if (method === 'DELETE' && path.match(/^\/api\/user\/remove-guardian\/\w+$/)) return 'Remove User Guardian';
        if (method === 'POST' && path === '/api/user/guardian/bind-request') return 'Request Guardian Bind';
        if (method === 'POST' && path === '/api/user/guardian/bind-confirm') return 'Confirm Guardian Bind';
        if (method === 'GET' && path === '/api/user/guardian/bound-users') return 'Get Bound Users';
        if (method === 'GET' && path === '/api/user/guardian/scan-stats') return 'Get Guardian Scan Stats';
        if (method === 'GET' && path === '/api/user/guardian/all-scans/user') return 'Get Scans By User for Guardian';
        if (method === 'POST' && path === '/api/user/guardian/llm-ask-question') return 'Guardian Ask LLM';
        if (method === 'GET' && path.match(/^\/api\/user\/guardian\/\w+\/image$/)) return 'Get Conversation Image for Guardian';
        if (method === 'GET' && path.match(/^\/api\/user\/guardian\/conversation\/\w+\/history$/)) return 'Get Conversation History for Guardian';

        // Admin Routes
        if (method === 'POST' && path === '/api/admin/users') return 'Admin: Create User';
        if (method === 'GET' && path === '/api/admin/users') return 'Admin: List Users';
        if (method === 'GET' && path.match(/^\/api\/admin\/users\/\w+$/)) return 'Admin: Get User By ID';
        if (method === 'PUT' && path.match(/^\/api\/admin\/users\/\w+$/)) return 'Admin: Update User';
        if (method === 'DELETE' && path.match(/^\/api\/admin\/users\/\w+$/)) return 'Admin: Delete User';
        if (method === 'GET' && path.match(/^\/api\/admin\/users\/\w+\/scans$/)) return 'Admin: Get User Scans';
        if (method === 'GET' && path.match(/^\/api\/admin\/scans\/\w+\/images$/)) return 'Admin: Get Conversation Images';
        if (method === 'GET' && path.match(/^\/api\/admin\/conversations\/\w+\/history$/)) return 'Admin: Get Conversation History';
        if (method === 'PUT' && path.match(/^\/api\/admin\/scans\/\w+$/)) return 'Admin: Update Scan';
        if (method === 'DELETE' && path.match(/^\/api\/admin\/scans\/\w+$/)) return 'Admin: Delete Scan';
        if (method === 'GET' && path === '/api/admin/dashboard') return 'Admin: Get Dashboard Stats';
        if (method === 'GET' && path === '/api/admin/report') return 'Admin: Generate Report';
        if (method === 'GET' && path.match(/^\/api\/users\/\w+\/guardians$/)) return 'Admin: Get User Guardians';
        if (method === 'POST' && path.match(/^\/api\/users\/\w+\/guardians$/)) return 'Admin: Bind Guardian';
        if (method === 'DELETE' && path.match(/^\/api\/users\/\w+\/guardians\/\w+$/)) return 'Admin: Unbind Guardian';
        if (method === 'GET' && path === '/api/admin/audit-trail') return 'Admin: Get Audit Trail';
        if (method === 'GET' && path.match(/^\/api\/admin\/users\/\w+\/logs$/)) return 'Admin: Get User Logs';

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