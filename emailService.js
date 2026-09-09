import nodemailer from 'nodemailer';
import 'dotenv/config';

// Create Transporter
let transporter = null;

const createEmailTransporter = async () => {
  if (transporter) return transporter;

  const host = process.env.SMTP_HOST || 'smtp.gmail.com';
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const secure = process.env.SMTP_SECURE === 'true' || port === 465;

  if (user && pass) {
    // Configured production SMTP
    transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user, pass }
    });
    console.log(`📧 Nodemailer: Configured with SMTP Host: ${host}:${port} (${user})`);
  } else {
    // Development fallback transporter (Ethereal test email / console logger)
    try {
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      });
      console.log(`📧 Nodemailer: Running with Ethereal Dev Account (${testAccount.user})`);
    } catch (err) {
      // JSON Transport fallback if network to ethereal is unavailable
      transporter = nodemailer.createTransport({
        jsonTransport: true
      });
      console.log('📧 Nodemailer: Running in local JSON stream transport mode');
    }
  }

  return transporter;
};

/**
 * Send 6-Digit OTP Verification Email
 */
export const sendOtpEmail = async ({ toEmail, name, otp }) => {
  const mailer = await createEmailTransporter();
  const fromAddress = process.env.SMTP_FROM || '"Discipline Tracker" <noreply@disciplinetracker.com>';
  const recipientName = name || 'Discipline Athlete';

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Your Verification Code</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px; color: #1e293b; }
        .email-card { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.06); }
        .email-header { background: linear-gradient(135deg, #10b981, #059669); padding: 32px 24px; text-align: center; color: #ffffff; }
        .logo-icon { font-size: 38px; display: inline-block; margin-bottom: 6px; }
        .app-title { font-size: 20px; font-weight: 800; margin: 0; letter-spacing: -0.5px; }
        .email-body { padding: 32px 28px; }
        .greeting { font-size: 17px; font-weight: 700; color: #0f172a; margin-top: 0; }
        .message-text { font-size: 14.5px; color: #475569; line-height: 1.6; margin: 12px 0 24px; }
        .otp-box { background: #f0fdf4; border: 2px dashed #10b981; border-radius: 12px; padding: 20px; text-align: center; margin: 24px 0; }
        .otp-label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #059669; margin-bottom: 6px; }
        .otp-code { font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #0f172a; font-family: 'SFMono-Regular', Consolas, Menlo, monospace; margin: 0; }
        .expiry-text { font-size: 12.5px; color: #64748b; margin-top: 8px; }
        .security-notice { font-size: 12px; color: #94a3b8; border-top: 1px solid #f1f5f9; padding-top: 20px; margin-top: 28px; line-height: 1.5; }
        .email-footer { background: #f8fafc; padding: 18px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #f1f5f9; }
      </style>
    </head>
    <body>
      <div class="email-card">
        <div class="email-header">
          <div class="logo-icon">🔥</div>
          <h1 class="app-title">Discipline Tracker</h1>
        </div>
        
        <div class="email-body">
          <h2 class="greeting">Hi ${recipientName}! 👋</h2>
          <p class="message-text">
            Welcome to <strong>Discipline Tracker</strong>. To complete your signup and secure your account, please enter the one-time verification code (OTP) below:
          </p>

          <div class="otp-box">
            <div class="otp-label">Your One-Time Verification Code</div>
            <div class="otp-code">${otp}</div>
            <div class="expiry-text">⏳ Valid for <strong>10 minutes</strong></div>
          </div>

          <div class="security-notice">
            🔒 <strong>Security Warning:</strong> Never share this code with anyone. Discipline Tracker staff will never ask for your verification code. If you did not request this email, you can safely disregard it.
          </div>
        </div>

        <div class="email-footer">
          &copy; ${new Date().getFullYear()} Discipline Tracker &bull; Built for peak daily consistency.
        </div>
      </div>
    </body>
    </html>
  `;

  const info = await mailer.sendMail({
    from: fromAddress,
    to: toEmail,
    subject: `🔐 ${otp} is your Discipline Tracker Verification Code`,
    text: `Your Discipline Tracker OTP code is: ${otp}. It is valid for 10 minutes.`,
    html: htmlContent
  });

  console.log(`[OTP Sent] ✉️ Code sent to: ${toEmail} | Message ID: ${info.messageId || 'local'}`);
  if (nodemailer.getTestMessageUrl && info) {
    const testUrl = nodemailer.getTestMessageUrl(info);
    if (testUrl) {
      console.log(`[Preview Email URL]: ${testUrl}`);
    }
  }

  return { success: true, messageId: info.messageId };
};

/**
 * Send Password Reset OTP Email
 */
export const sendPasswordResetOtpEmail = async ({ toEmail, name, otp }) => {
  const mailer = await createEmailTransporter();
  const fromAddress = process.env.SMTP_FROM || '"Discipline Tracker" <noreply@disciplinetracker.com>';
  const recipientName = name || 'Discipline Athlete';

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px; color: #1e293b; }
        .email-card { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.06); }
        .email-header { background: linear-gradient(135deg, #0ea5e9, #0284c7); padding: 32px 24px; text-align: center; color: #ffffff; }
        .logo-icon { font-size: 38px; display: inline-block; margin-bottom: 6px; }
        .app-title { font-size: 20px; font-weight: 800; margin: 0; letter-spacing: -0.5px; }
        .email-body { padding: 32px 28px; }
        .greeting { font-size: 17px; font-weight: 700; color: #0f172a; margin-top: 0; }
        .message-text { font-size: 14.5px; color: #475569; line-height: 1.6; margin: 12px 0 24px; }
        .otp-box { background: #f0f9ff; border: 2px dashed #0284c7; border-radius: 12px; padding: 20px; text-align: center; margin: 24px 0; }
        .otp-label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #0284c7; margin-bottom: 6px; }
        .otp-code { font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #0f172a; font-family: 'SFMono-Regular', Consolas, Menlo, monospace; margin: 0; }
        .expiry-text { font-size: 12.5px; color: #64748b; margin-top: 8px; }
        .security-notice { font-size: 12px; color: #94a3b8; border-top: 1px solid #f1f5f9; padding-top: 20px; margin-top: 28px; line-height: 1.5; }
        .email-footer { background: #f8fafc; padding: 18px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #f1f5f9; }
      </style>
    </head>
    <body>
      <div class="email-card">
        <div class="email-header">
          <div class="logo-icon">🔐</div>
          <h1 class="app-title">Password Reset Request</h1>
        </div>
        
        <div class="email-body">
          <h2 class="greeting">Hi ${recipientName}!</h2>
          <p class="message-text">
            We received a request to reset the password for your <strong>Discipline Tracker</strong> account. Enter the 6-digit code below to set a new password:
          </p>

          <div class="otp-box">
            <div class="otp-label">Your Password Reset Code</div>
            <div class="otp-code">${otp}</div>
            <div class="expiry-text">⏳ Valid for <strong>10 minutes</strong></div>
          </div>

          <div class="security-notice">
            🔒 <strong>Security Notice:</strong> If you did not request a password reset, you can safely ignore this email. Your password will remain unchanged.
          </div>
        </div>

        <div class="email-footer">
          &copy; ${new Date().getFullYear()} Discipline Tracker &bull; Account Security
        </div>
      </div>
    </body>
    </html>
  `;

  const info = await mailer.sendMail({
    from: fromAddress,
    to: toEmail,
    subject: `🔐 ${otp} is your Discipline Tracker Password Reset Code`,
    text: `Your password reset code is: ${otp}. It is valid for 10 minutes.`,
    html: htmlContent
  });

  console.log(`[Password Reset OTP Sent] ✉️ Code sent to: ${toEmail} | Message ID: ${info.messageId || 'local'}`);
  return { success: true, messageId: info.messageId };
};


