const pool = require('../db');

// AUDIT MIDDLEWARE
const auditLog = async (req, res, next) => {

  const originalSend = res.send;
  res.send = async function (body) {
    originalSend.apply(res, arguments);

    
    const getAction = (method, path) => {
        // Auth Routes
        if (method === 'POST' && /^(\/api)?\/auth\/signup\/?$/.test(path)) return 'Account: User Registration';
        if (method === 'POST' && /^(\/api)?\/auth\/login\/?$/.test(path)) return 'Account: User Login';
        if (method === 'POST' && /^(\/api)?\/auth\/forgot-password\/?$/.test(path)) return 'Account: Initiated Password Reset';
        if (method === 'POST' && /^(\/api)?\/auth\/reset-password\/?$/.test(path)) return 'Account: Completed Password Reset';
        if (method === 'POST' && /^(\/api)?\/auth\/verify-login\/?$/.test(path)) return 'Account: Verified OTP for Login';
        if (method === 'POST' && /^(\/api)?\/auth\/resend-otp\/?$/.test(path)) return 'Account: Requested New OTP';

        // User Routes
        if (method === 'GET' && /^(\/api)?\/user\/dashboard\/?$/.test(path)) return 'User: Viewed Dashboard';
        if (method === 'GET' && /^(\/api)?\/user\/profile\/?$/.test(path)) return 'User: Viewed Profile';
        if (method === 'POST' && /^(\/api)?\/user\/ocr-scans\/?$/.test(path)) return 'Scan: Created OCR Scan';
        if (method === 'POST' && /^(\/api)?\/user\/object-scans\/?$/.test(path)) return 'Scan: Created Object Scan';
        if (method === 'GET' && /^(\/api)?\/user\/scans\/?$/.test(path)) return 'Scan: Viewed All Scans';
        if (method === 'GET' && /^(\/api)?\/user\/scans\/[^/]+\/?$/.test(path)) return 'Scan: Viewed Single Scan';
        if (method === 'PUT' && /^(\/api)?\/user\/scans\/[^/]+\/?$/.test(path)) return 'Scan: Updated Scan Details';
        if (method === 'DELETE' && /^(\/api)?\/user\/scans\/[^/]+\/?$/.test(path)) return 'Scan: Deleted Scan';
        if (method === 'POST' && /^(\/api)?\/user\/photo-upload\/?$/.test(path)) return 'LLM: Uploaded Photo for Analysis';
        if (method === 'POST' && /^(\/api)?\/user\/llm-ask-question\/?$/.test(path)) return 'LLM: Asked a Question';
        if (method === 'GET' && /^(\/api)?\/user\/get-guardians\/?$/.test(path)) return 'Guardian: Viewed Guardians';
        if (method === 'DELETE' && /^(\/api)?\/user\/remove-guardian\/[^/]+\/?$/.test(path)) return 'Guardian: Removed Guardian';
        if (method === 'POST' && /^(\/api)?\/user\/guardian\/bind-request\/?$/.test(path)) return 'Guardian: Sent Binding Request';
        if (method === 'POST' && /^(\/api)?\/user\/guardian\/bind-confirm\/?$/.test(path)) return 'Guardian: Confirmed Binding Request';
        if (method === 'GET' && /^(\/api)?\/user\/guardian\/bound-users\/?$/.test(path)) return 'Guardian: Viewed Bound Users';
        if (method === 'GET' && /^(\/api)?\/user\/guardian\/scan-stats\/?$/.test(path)) return 'Guardian: Viewed Scan Statistics';
        if (method === 'GET' && /^(\/api)?\/user\/guardian\/all-scans\/user\/?$/.test(path)) return 'Guardian: Viewed Scans of a User';
        if (method === 'POST' && /^(\/api)?\/user\/guardian\/llm-ask-question\/?$/.test(path)) return 'Guardian: Asked LLM a Question';
        if (method === 'GET' && /^(\/api)?\/user\/guardian\/[^/]+\/image\/?$/.test(path)) return 'Guardian: Viewed Conversation Image';
        if (method === 'GET' && /^(\/api)?\/user\/guardian\/conversation\/[^/]+\/history\/?$/.test(path)) return 'Guardian: Viewed Conversation History';
        if (method === 'GET' && /^(\/api)?\/user\/premium\/status\/?$/.test(path)) return 'User: Checked Premium Status';
        if (method === 'POST' && /^(\/api)?\/user\/premium\/purchase\/?$/.test(path)) return 'User: Purchased Premium';
        if (method === 'PUT' && /^(\/api)?\/user\/guardian\/scans\/[^/]+\/voice\/?$/.test(path)) return 'Guardian: Updated/Added Scan Voice Note';
        if (method === 'GET' && /^(\/api)?\/user\/guardian\/scans\/[^/]+\/voice\/?$/.test(path)) return 'Guardian: Fetched Scan Voice Note';

        // Admin Routes
        if (method === 'POST' && /^(\/api)?\/admin\/users\/?$/.test(path)) return 'Admin: Created a New User';
        if (method === 'GET' && /^(\/api)?\/admin\/users\/?$/.test(path)) return 'Admin: Viewed All Users';
        if (method === 'GET' && /^(\/api)?\/admin\/users\/[^/]+\/?$/.test(path)) return 'Admin: Viewed User Details';
        if (method === 'PUT' && /^(\/api)?\/admin\/users\/[^/]+\/?$/.test(path)) return 'Admin: Updated User Details';
        if (method === 'DELETE' && /^(\/api)?\/admin\/users\/[^/]+\/?$/.test(path)) return 'Admin: Deleted a User';
        if (method === 'GET' && /^(\/api)?\/admin\/users\/[^/]+\/scans\/?$/.test(path)) return 'Admin: Viewed User Scans';
        if (method === 'GET' && /^(\/api)?\/admin\/scans\/[^/]+\/images\/?$/.test(path)) return 'Admin: Viewed Conversation Images';
        if (method === 'GET' && /^(\/api)?\/admin\/conversations\/[^/]+\/history\/?$/.test(path)) return 'Admin: Viewed Conversation History';
        if (method === 'PUT' && /^(\/api)?\/admin\/scans\/[^/]+\/?$/.test(path)) return 'Admin: Updated Scan Details';
        if (method === 'DELETE' && /^(\/api)?\/admin\/scans\/[^/]+\/?$/.test(path)) return 'Admin: Deleted a Scan';
        if (method === 'GET' && /^(\/api)?\/admin\/dashboard\/?$/.test(path)) return 'Admin: Viewed Dashboard';
        if (method === 'GET' && /^(\/api)?\/admin\/report\/?$/.test(path)) return 'Admin: Generated a Report';
        if (method === 'GET' && /^(\/api)?\/admin\/users\/[^/]+\/guardians\/?$/.test(path)) return 'Admin: Viewed User Guardians';
        if (method === 'POST' && /^(\/api)?\/admin\/users\/[^/]+\/guardians\/?$/.test(path)) return 'Admin: Bound a Guardian to a User';
        if (method === 'DELETE' && /^(\/api)?\/admin\/users\/[^/]+\/guardians\/[^/]+\/?$/.test(path)) return 'Admin: Unbound a Guardian from a User';
        if (method === 'GET' && /^(\/api)?\/admin\/audit-trail\/?$/.test(path)) return 'Admin: Viewed Audit Trail';
        if (method === 'GET' && /^(\/api)?\/admin\/users\/[^/]+\/logs\/?$/.test(path)) return 'Admin: Viewed User Logs';
        if (method === 'GET' && /^(\/api)?\/admin\/guardians\/?$/.test(path)) return 'Admin: Viewed All Guardians';
        if (method === 'GET' && /^(\/api)?\/admin\/guardians\/[^/]+\/bound-users\/?$/.test(path)) return 'Admin: Viewed Users Bound to a Guardian';
        if (method === 'GET' && /^(\/api)?\/admin\/users\/[^/]+\/transactions\/?$/.test(path)) return 'Admin: Viewed User Transactions';
        if (method === 'PUT' && /^(\/api)?\/admin\/users\/[^/]+\/make-premium\/?$/.test(path)) return 'Admin: Made User Premium';
        if (method === 'PUT' && /^(\/api)?\/admin\/users\/[^/]+\/remove-premium\/?$/.test(path)) return 'Admin: Removed User Premium';
        if (method === 'GET' && /^(\/api)?\/admin\/users\/[^/]+\/activity\/?$/.test(path)) return 'Admin: Viewed User Activity';
 
         return `Unknown action for ${method} ${path}`;
     };

    const getStatus = (statusCode) => {
      if ((statusCode >= 200 && statusCode < 300) || statusCode === 304) {
        return 'SUCCESS';
      }
      return 'FAIL';
    };
    
    const { deviceModel, deviceType } = req.deviceInfo || {};
    console.log(req.deviceInfo)
    let userAgent = req.headers['user-agent'];
    if (deviceModel && deviceType) {
      userAgent = `${userAgent} (Device Model: ${deviceModel}, Device Type: ${deviceType})`;
    }

    const action = getAction(req.method, req.originalUrl.split('?')[0]);

    if (action === 'Admin: Viewed Audit Trail' || action === 'Admin: Viewed User Scans') {
      return;
    }

    const logData = {
      changed_by: req.user ? req.user.user_id : null,
      action: action,
      status: getStatus(res.statusCode),
      endpoint: req.originalUrl,
      method: req.method,
      request_body: '{}',
      response_status: res.statusCode,
      ip_address: (req.headers['x-forwarded-for'] || req.ip).split(',')[0].trim(),
      user_agent: userAgent,
      changed_at: new Date()
    };

    try {
      await pool.execute(
        'INSERT INTO CSB.AUDIT_TRAIL (changed_by, action, status, endpoint, method, request_body, response_status, ip_address, user_agent, changedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [logData.changed_by, logData.action, logData.status, logData.endpoint, logData.method, logData.request_body, logData.response_status, logData.ip_address, logData.user_agent, logData.changed_at]
      );
    } catch (error) {
        if (error.code === 'ER_DATA_TOO_LONG') {
            const truncatedBody = logData.request_body.substring(0, 2000);
            pool.execute(
                'INSERT INTO CSB.AUDIT_TRAIL (changed_by, action, status, endpoint, method, request_body, response_status, ip_address, user_agent, changedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [logData.changed_by, logData.action, logData.status, logData.endpoint, logData.method, truncatedBody, logData.response_status, logData.ip_address, logData.user_agent, logData.changed_at]
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