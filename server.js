const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Email transporter
const emailTransporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Middleware
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",") || [
      "http://localhost:3000",
      "http://localhost:3001",
      "https://yourdomain.com",
    ],
    credentials: true,
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests, please try again later." },
});
app.use(limiter);

// Body parsing
app.use("/webhook/paddle", express.raw({ type: "application/json" }));
app.use(express.json());

// Utility functions
const generateLicenseKey = (licenseId, type, expiryDate) => {
  const licenseData = {
    licenseId,
    type,
    issuedAt: new Date().toISOString(),
    expiryDate: expiryDate ? expiryDate.toISOString() : null,
    features: {
      aiGeneration: true,
      premiumTemplates: true,
      advancedExport: type !== "trial",
      watermark: type === "trial",
    },
  };

  return jwt.sign(licenseData, process.env.LICENSE_SECRET);
};

const verifyWebhookSignature = (signature, body) => {
  try {
    const expectedSignature = crypto
      .createHmac("sha256", process.env.PADDLE_WEBHOOK_SECRET)
      .update(body)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(signature, "hex"),
      Buffer.from(expectedSignature, "hex")
    );
  } catch (error) {
    return false;
  }
};

const sendLicenseEmail = async (
  email,
  licenseKey,
  isTrial = false,
  customerName = ""
) => {
  try {
    const subject = isTrial
      ? "Your Manga AI Studio 7-Day Free Trial License"
      : "Your Manga AI Studio License";

    const trialText = isTrial
      ? `
      <p>Your <strong>7-day free trial</strong> has been activated. After the trial period, 
      your subscription will automatically continue unless canceled.</p>
      <p><strong>Trial End Date:</strong> ${new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
      ).toLocaleDateString()}</p>
    `
      : "";

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .license-box { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
          .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; 
                   text-decoration: none; border-radius: 5px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Welcome to Manga AI Studio! 🎨</h2>
          <p>Dear ${customerName || "Customer"},</p>
          
          ${trialText}
          
          <p>Your license key is ready. Use it to activate the desktop application:</p>
          
          <div class="license-box">
            <strong>License Key:</strong><br>
            <code style="font-size: 18px; letter-spacing: 1px;">${licenseKey}</code>
          </div>

          <h3>Next Steps:</h3>
          <ol>
            <li>Download the Manga AI Studio desktop application</li>
            <li>Install and launch the application</li>
            <li>Enter your license key when prompted</li>
            <li>Start creating amazing manga art!</li>
          </ol>

          <a href="https://yourdomain.com/download" class="button">Download Desktop App</a>

          <p><strong>Need Help?</strong><br>
          Contact our support team: support@yourdomain.com</p>

          <p>Happy creating!<br>The Manga AI Team</p>
        </div>
      </body>
      </html>
    `;

    await emailTransporter.sendMail({
      from: `"Manga AI Studio" <${process.env.SMTP_FROM}>`,
      to: email,
      subject: subject,
      html: html,
    });

    console.log(`License email sent to ${email}`);
  } catch (error) {
    console.error("Email sending error:", error);
  }
};

// Routes
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    service: "Manga AI License Server",
  });
});

// License Activation
app.post("/api/activate", async (req, res) => {
  try {
    const { licenseKey, deviceId, deviceInfo } = req.body;

    if (!licenseKey || !deviceId) {
      return res.status(400).json({
        success: false,
        error: "License key and device ID are required",
      });
    }

    // Verify license signature
    let licenseData;
    try {
      licenseData = jwt.verify(licenseKey, process.env.LICENSE_SECRET);
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: "Invalid license key",
      });
    }

    // Get license from database
    const { data: license, error: licenseError } = await supabase
      .from("licenses")
      .select("*")
      .eq("id", licenseData.licenseId)
      .single();

    if (licenseError || !license) {
      return res.status(404).json({
        success: false,
        error: "License not found",
      });
    }

    // Check license status
    if (!["active", "trialing"].includes(license.status)) {
      return res.status(403).json({
        success: false,
        error: `License is ${license.status}`,
        status: license.status,
      });
    }

    // Check expiration
    if (license.expires_at) {
      const now = new Date();
      const expiryDate = new Date(license.expires_at);

      if (now > expiryDate) {
        await supabase
          .from("licenses")
          .update({ status: "expired" })
          .eq("id", license.id);

        return res.status(403).json({
          success: false,
          error: "License has expired",
        });
      }
    }

    // Check existing activation
    const { data: existingActivation } = await supabase
      .from("activations")
      .select("*")
      .eq("license_id", license.id)
      .eq("device_id", deviceId)
      .eq("is_active", true)
      .single();

    if (existingActivation) {
      await supabase
        .from("activations")
        .update({
          last_validation: new Date().toISOString(),
          device_info: deviceInfo || existingActivation.device_info,
        })
        .eq("id", existingActivation.id);

      return res.json({
        success: true,
        activated: true,
        licenseType: license.type,
        expiresAt: license.expires_at,
        features: licenseData.features,
        message: "Device already activated",
      });
    }

    // Check activation limit
    const { count: activeCount, error: countError } = await supabase
      .from("activations")
      .select("*", { count: "exact", head: true })
      .eq("license_id", license.id)
      .eq("is_active", true);

    if (countError) throw countError;

    if (activeCount >= license.max_activations) {
      return res.status(403).json({
        success: false,
        error: "Maximum number of devices reached",
        maxDevices: license.max_activations,
        currentDevices: activeCount,
      });
    }

    // Create new activation
    const { data: activation, error: activationError } = await supabase
      .from("activations")
      .insert([
        {
          license_id: license.id,
          device_id: deviceId,
          device_info: deviceInfo || {},
          activated_at: new Date().toISOString(),
          last_validation: new Date().toISOString(),
          is_active: true,
        },
      ])
      .select()
      .single();

    if (activationError) throw activationError;

    res.json({
      success: true,
      activated: true,
      licenseType: license.type,
      expiresAt: license.expires_at,
      features: licenseData.features,
      activationId: activation.id,
      message: "License activated successfully",
    });
  } catch (error) {
    console.error("Activation error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

// License Validation
app.post("/api/validate", async (req, res) => {
  try {
    const { licenseKey, deviceId } = req.body;

    if (!licenseKey || !deviceId) {
      return res.status(400).json({
        success: false,
        error: "License key and device ID are required",
        valid: false,
      });
    }

    // Verify license signature
    let licenseData;
    try {
      licenseData = jwt.verify(licenseKey, process.env.LICENSE_SECRET);
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: "Invalid license key",
        valid: false,
      });
    }

    // Get license from database
    const { data: license, error: licenseError } = await supabase
      .from("licenses")
      .select("*")
      .eq("id", licenseData.licenseId)
      .single();

    if (licenseError || !license) {
      return res.status(404).json({
        success: false,
        error: "License not found",
        valid: false,
      });
    }

    // Check license status
    if (!["active", "trialing"].includes(license.status)) {
      return res.status(403).json({
        success: false,
        error: `License is ${license.status}`,
        valid: false,
        status: license.status,
      });
    }

    // Check expiration
    if (license.expires_at) {
      const now = new Date();
      const expiryDate = new Date(license.expires_at);

      if (now > expiryDate) {
        await supabase
          .from("licenses")
          .update({ status: "expired" })
          .eq("id", license.id);

        return res.status(403).json({
          success: false,
          error: "License has expired",
          valid: false,
        });
      }
    }

    // Check device activation
    const { data: activation, error: activationError } = await supabase
      .from("activations")
      .select("*")
      .eq("license_id", license.id)
      .eq("device_id", deviceId)
      .eq("is_active", true)
      .single();

    if (activationError || !activation) {
      return res.status(403).json({
        success: false,
        error: "License not activated on this device",
        valid: false,
        needsActivation: true,
      });
    }

    // Update last validation
    await supabase
      .from("activations")
      .update({ last_validation: new Date().toISOString() })
      .eq("id", activation.id);

    const remainingDays = license.expires_at
      ? Math.ceil(
          (new Date(license.expires_at) - new Date()) / (1000 * 60 * 60 * 24)
        )
      : null;

    res.json({
      success: true,
      valid: true,
      licenseType: license.type,
      expiresAt: license.expires_at,
      features: licenseData.features,
      remainingDays,
      status: license.status,
      lastValidation: activation.last_validation,
    });
  } catch (error) {
    console.error("Validation error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      valid: false,
    });
  }
});

// Deactivate License
app.post("/api/deactivate", async (req, res) => {
  try {
    const { licenseKey, deviceId } = req.body;

    if (!licenseKey || !deviceId) {
      return res.status(400).json({
        success: false,
        error: "License key and device ID are required",
      });
    }

    let licenseData;
    try {
      licenseData = jwt.verify(licenseKey, process.env.LICENSE_SECRET);
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: "Invalid license key",
      });
    }

    const { error: deactivateError } = await supabase
      .from("activations")
      .update({
        is_active: false,
        deactivated_at: new Date().toISOString(),
      })
      .eq("license_id", licenseData.licenseId)
      .eq("device_id", deviceId);

    if (deactivateError) throw deactivateError;

    res.json({
      success: true,
      deactivated: true,
      message: "License deactivated on this device",
    });
  } catch (error) {
    console.error("Deactivation error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

// Get License Info
app.post("/api/license/info", async (req, res) => {
  try {
    const { licenseKey } = req.body;

    if (!licenseKey) {
      return res.status(400).json({ error: "License key is required" });
    }

    let licenseData;
    try {
      licenseData = jwt.verify(licenseKey, process.env.LICENSE_SECRET);
    } catch (error) {
      return res.status(401).json({ error: "Invalid license key" });
    }

    const { data: license, error: licenseError } = await supabase
      .from("licenses")
      .select(
        `
        *,
        activations (
          device_id,
          activated_at,
          device_info,
          is_active
        )
      `
      )
      .eq("id", licenseData.licenseId)
      .single();

    if (licenseError || !license) {
      return res.status(404).json({ error: "License not found" });
    }

    const activeActivations = license.activations.filter((a) => a.is_active);

    res.json({
      licenseId: license.id,
      type: license.type,
      status: license.status,
      expiresAt: license.expires_at,
      maxActivations: license.max_activations,
      activations: activeActivations,
      totalActivations: license.activations.length,
      activeActivations: activeActivations.length,
    });
  } catch (error) {
    console.error("License info error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Paddle Webhook Handler
app.post("/webhook/paddle", async (req, res) => {
  let event;

  try {
    const signature = req.headers["paddle-signature"];
    if (!signature) {
      return res.status(401).json({ error: "Missing signature" });
    }

    if (!verifyWebhookSignature(signature, req.body)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    event = JSON.parse(req.body.toString());
    console.log("Webhook received:", event.event_type);

    await handleWebhookEvent(event);

    res.status(200).json({ received: true });
  } catch (error) {
    console.error("Webhook error:", error);
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

// Webhook Event Handler
async function handleWebhookEvent(event) {
  switch (event.event_type) {
    case "subscription.created":
      await handleSubscriptionCreated(event.data);
      break;
    case "subscription.updated":
      await handleSubscriptionUpdated(event.data);
      break;
    case "subscription.canceled":
      await handleSubscriptionCanceled(event.data);
      break;
    case "subscription.payment_failed":
      await handleSubscriptionPaymentFailed(event.data);
      break;
    case "transaction.completed":
      await handleTransactionCompleted(event.data);
      break;
    default:
      console.log("Unhandled event:", event.event_type);
  }
}

async function handleSubscriptionCreated(subscription) {
  try {
    const isTrial = subscription.status === "trialing";
    const expiresAt = isTrial
      ? new Date(subscription.trial_ends_at)
      : new Date(subscription.next_billed_at);

    const licenseKey = await createLicense({
      type: "subscription",
      customerEmail: subscription.customer_email,
      customerName: subscription.customer_name,
      subscriptionId: subscription.id,
      expiresAt: expiresAt,
      maxActivations: 3,
      isTrial: isTrial,
      status: "active",
    });

    console.log(
      `Subscription license created for ${subscription.customer_email}`
    );
  } catch (error) {
    console.error("Subscription created error:", error);
  }
}

async function handleSubscriptionUpdated(subscription) {
  try {
    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (license) {
      const updates = {
        status: subscription.status === "active" ? "active" : "inactive",
      };

      if (subscription.next_billed_at) {
        updates.expires_at = new Date(
          subscription.next_billed_at
        ).toISOString();
      }

      await supabase.from("licenses").update(updates).eq("id", license.id);
    }
  } catch (error) {
    console.error("Subscription updated error:", error);
  }
}

async function handleSubscriptionCanceled(subscription) {
  try {
    await supabase
      .from("licenses")
      .update({
        status: "canceled",
        canceled_at: new Date().toISOString(),
      })
      .eq("subscription_id", subscription.id);
  } catch (error) {
    console.error("Subscription canceled error:", error);
  }
}

async function handleSubscriptionPaymentFailed(subscription) {
  try {
    await supabase
      .from("licenses")
      .update({ status: "past_due" })
      .eq("subscription_id", subscription.id);
  } catch (error) {
    console.error("Subscription payment failed error:", error);
  }
}

async function handleTransactionCompleted(transaction) {
  try {
    if (!transaction.subscription_id) {
      const licenseKey = await createLicense({
        type: "one_time",
        customerEmail: transaction.customer_email,
        customerName: transaction.customer_name,
        transactionId: transaction.id,
        maxActivations: 1,
        status: "active",
      });

      console.log(`One-time license created for ${transaction.customer_email}`);
    }
  } catch (error) {
    console.error("Transaction completed error:", error);
  }
}

async function createLicense({
  type,
  customerEmail,
  customerName,
  transactionId,
  subscriptionId,
  expiresAt,
  maxActivations,
  isTrial = false,
  status = "active",
}) {
  const { data: license, error } = await supabase
    .from("licenses")
    .insert([
      {
        type,
        status,
        customer_email: customerEmail,
        transaction_id: transactionId,
        subscription_id: subscriptionId,
        expires_at: expiresAt ? expiresAt.toISOString() : null,
        max_activations: maxActivations,
        is_trial: isTrial,
        created_at: new Date().toISOString(),
      },
    ])
    .select()
    .single();

  if (error) throw error;

  const licenseKey = generateLicenseKey(license.id, type, expiresAt);

  await supabase
    .from("licenses")
    .update({ license_key: licenseKey })
    .eq("id", license.id);

  // Send email with license key
  await sendLicenseEmail(customerEmail, licenseKey, isTrial, customerName);

  return licenseKey;
}

// Error handling
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({
    success: false,
    error: "Internal server error",
  });
});

app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found",
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Manga AI License Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(
    `🌐 CORS enabled for: ${process.env.ALLOWED_ORIGINS || "localhost"}`
  );
});
