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
        if (method === 'POST' && path === '/api/auth/signup') return 'Account: User Registration';
        if (method === 'POST' && path === '/api/auth/login') return 'Account: User Login';
        if (method === 'POST' && path === '/api/auth/forgot-password') return 'Account: Initiated Password Reset';
        if (method === 'POST' && path === '/api/auth/reset-password') return 'Account: Completed Password Reset';
        if (method === 'POST' && path === '/api/auth/verify-login') return 'Account: Verified OTP for Login';
        if (method === 'POST' && path === '/api/auth/resend-otp') return 'Account: Requested New OTP';

        // User Routes
        if (method === 'GET' && path === '/api/user/dashboard') return 'User: Viewed Dashboard';
        if (method === 'GET' && path === '/api/user/profile') return 'User: Viewed Profile';
        if (method === 'POST' && path === '/api/user/ocr-scans') return 'Scan: Created OCR Scan';
        if (method === 'POST' && path === '/api/user/object-scans') return 'Scan: Created Object Scan';
        if (method === 'GET' && path === '/api/user/scans') return 'Scan: Viewed All Scans';
        if (method === 'GET' && path.match(/^\/api\/user\/scans\/[^/]+$/)) return 'Scan: Viewed Single Scan';
        if (method === 'PUT' && path.match(/^\/api\/user\/scans\/[^/]+$/)) return 'Scan: Updated Scan Details';
        if (method === 'DELETE' && path.match(/^\/api\/user\/scans\/[^/]+$/)) return 'Scan: Deleted Scan';
        if (method === 'POST' && path === '/api/user/photo-upload') return 'LLM: Uploaded Photo for Analysis';
        if (method === 'POST' && path === '/api/user/llm-ask-question') return 'LLM: Asked a Question';
        if (method === 'GET' && path === '/api/user/get-guardians') return 'Guardian: Viewed Guardians';
        if (method === 'DELETE' && path.match(/^\/api\/user\/remove-guardian\/[^/]+$/)) return 'Guardian: Removed Guardian';
        if (method === 'POST' && path === '/api/user/guardian/bind-request') return 'Guardian: Sent Binding Request';
        if (method === 'POST' && path === '/api/user/guardian/bind-confirm') return 'Guardian: Confirmed Binding Request';
        if (method === 'GET' && path === '/api/user/guardian/bound-users') return 'Guardian: Viewed Bound Users';
        if (method === 'GET' && path === '/api/user/guardian/scan-stats') return 'Guardian: Viewed Scan Statistics';
        if (method === 'GET' && path === '/api/user/guardian/all-scans/user') return 'Guardian: Viewed Scans of a User';
        if (method === 'POST' && path === '/api/user/guardian/llm-ask-question') return 'Guardian: Asked LLM a Question';
        if (method === 'GET' && path.match(/^\/api\/user\/guardian\/[^/]+\/image$/)) return 'Guardian: Viewed Conversation Image';
        if (method === 'GET' && path.match(/^\/api\/user\/guardian\/conversation\/[^/]+\/history$/)) return 'Guardian: Viewed Conversation History';

        // Admin Routes
        if (method === 'POST' && path === '/api/admin/users') return 'Admin: Created a New User';
        if (method === 'GET' && path === '/api/admin/users') return 'Admin: Viewed All Users';
        if (method === 'GET' && path.match(/^\/api\/admin\/users\/[^/]+$/)) return 'Admin: Viewed User Details';
        if (method === 'PUT' && path.match(/^\/api\/admin\/users\/[^/]+$/)) return 'Admin: Updated User Details';
        if (method === 'DELETE' && path.match(/^\/api\/admin\/users\/[^/]+$/)) return 'Admin: Deleted a User';
        if (method === 'GET' && path.match(/^\/api\/admin\/users\/[^/]+\/scans$/)) return 'Admin: Viewed User Scans';
        if (method === 'GET' && path.match(/^\/api\/admin\/scans\/[^/]+\/images$/)) return 'Admin: Viewed Conversation Images';
        if (method === 'GET' && path.match(/^\/api\/admin\/conversations\/[^/]+\/history$/)) return 'Admin: Viewed Conversation History';
        if (method === 'PUT' && path.match(/^\/api\/admin\/scans\/[^/]+$/)) return 'Admin: Updated Scan Details';
        if (method === 'DELETE' && path.match(/^\/api\/admin\/scans\/[^/]+$/)) return 'Admin: Deleted a Scan';
        if (method === 'GET' && path === '/api/admin/dashboard') return 'Admin: Viewed Dashboard';
        if (method === 'GET' && path === '/api/admin/report') return 'Admin: Generated a Report';
        if (method === 'GET' && path.match(/^\/api\/admin\/users\/[^/]+\/guardians$/)) return 'Admin: Viewed User Guardians';
        if (method === 'POST' && path.match(/^\/api\/admin\/users\/[^/]+\/guardians$/)) return 'Admin: Bound a Guardian to a User';
        if (method === 'DELETE' && path.match(/^\/api\/admin\/users\/[^/]+\/guardians\/[^/]+$/)) return 'Admin: Unbound a Guardian from a User';
        if (method === 'GET' && path === '/api/admin/audit-trail') return 'Admin: Viewed Audit Trail';
        if (method === 'GET' && path.match(/^\/api\/admin\/users\/[^/]+\/logs$/)) return 'Admin: Viewed User Logs';
        if (method === 'GET' && path === '/api/admin/guardians') return 'Admin: Viewed All Guardians';
        if (method === 'GET' && path.match(/^\/api\/admin\/guardians\/[^/]+\/bound-users$/)) return 'Admin: Viewed Users Bound to a Guardian';

        return `Unknown action for ${method} ${path}`;
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