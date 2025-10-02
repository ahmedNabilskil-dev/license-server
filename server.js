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
  process.env.SUPABASE_SERVICE_ROLE_KEY // ✅ Full access, bypasses RLS
);

// Email transporter
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // use TLS
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
app.set("trust proxy", 1);
// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests, please try again later." },
});
app.use(limiter);

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

function verifyWebhookSignature(signatureHeader, rawBody) {
  try {
    if (!signatureHeader) {
      console.error("Missing Paddle-Signature header");
      return false;
    }

    // Parse key=value pairs
    const parts = Object.fromEntries(
      signatureHeader.split(";").map((p) => p.split("="))
    );
    const { t: timestamp, v1: signatureHex } = parts;

    if (!timestamp || !signatureHex) {
      console.error("Invalid Paddle-Signature format", parts);
      return false;
    }

    // Freshness check (5 minutes)
    const now = Math.floor(Date.now() / 1000);
    if (now - parseInt(timestamp, 10) > 300) {
      console.error("Expired webhook (older than 5 min)");
      return false;
    }

    // Reconstruct signed payload
    const signedPayload = `${timestamp}:${rawBody}`;

    // Compute expected signature with your notification secret
    const expectedSignature = crypto
      .createHmac("sha256", process.env.PADDLE_NOTIFICATION_SECRET) // <- your pdl_ntfset_... key
      .update(signedPayload, "utf8")
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(signatureHex, "hex"),
      Buffer.from(expectedSignature, "hex")
    );
  } catch (err) {
    console.error("Signature verification failed:", err.message);
    return false;
  }
}

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

// Cancel subscription from app
app.post("/api/subscription/cancel", async (req, res) => {
  try {
    const { licenseKey, reason } = req.body;

    if (!licenseKey) {
      return res.status(400).json({
        success: false,
        error: "License key is required",
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

    // Check if it's a subscription
    if (license.type !== "subscription" || !license.subscription_id) {
      return res.status(400).json({
        success: false,
        error: "This is not a subscription license",
      });
    }

    // Check if already canceled
    if (license.status === "canceled") {
      return res.status(400).json({
        success: false,
        error: "Subscription is already canceled",
      });
    }

    // Cancel subscription via Paddle API
    try {
      const paddleResponse = await fetch(
        `https://api.paddle.com/subscriptions/${license.subscription_id}/cancel`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.PADDLE_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            effective_from: "next_billing_period", // or "immediately"
          }),
        }
      );

      if (!paddleResponse.ok) {
        const errorData = await paddleResponse.json();
        throw new Error(
          `Paddle API error: ${errorData.error?.message || "Unknown error"}`
        );
      }

      const paddleData = await paddleResponse.json();
      console.log("Paddle cancellation response:", paddleData);
    } catch (paddleError) {
      console.error("Paddle API cancellation failed:", paddleError);
      return res.status(500).json({
        success: false,
        error: "Failed to cancel subscription with payment provider",
        details: paddleError.message,
      });
    }

    // Update license in database
    const { error: updateError } = await supabase
      .from("licenses")
      .update({
        status: "canceled",
        canceled_at: new Date().toISOString(),
        cancellation_reason: reason || null,
      })
      .eq("id", license.id);

    if (updateError) throw updateError;

    // Deactivate all devices
    await supabase
      .from("activations")
      .update({
        is_active: false,
        deactivated_at: new Date().toISOString(),
      })
      .eq("license_id", license.id);

    // Send cancellation confirmation email
    await sendCancellationEmail(license.customer_email, license.customer_name);

    res.json({
      success: true,
      message: "Subscription canceled successfully",
      canceledAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Subscription cancellation error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

// Add cancellation email function
const sendCancellationEmail = async (email, customerName = "") => {
  try {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; 
                   text-decoration: none; border-radius: 5px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Subscription Canceled</h2>
          <p>Dear ${customerName || "Customer"},</p>
          
          <p>Your Manga AI Studio subscription has been canceled as requested.</p>
          
          <p><strong>What happens next:</strong></p>
          <ul>
            <li>You'll continue to have access until the end of your current billing period</li>
            <li>No further charges will be made</li>
            <li>Your license will expire at the end of the billing period</li>
          </ul>

          <p>We're sorry to see you go! If you change your mind, you can resubscribe at any time.</p>

          <a href="https://yourdomain.com/pricing" class="button">View Plans</a>

          <p><strong>Need Help?</strong><br>
          Contact our support team: support@yourdomain.com</p>

          <p>Best regards,<br>The Manga AI Team</p>
        </div>
      </body>
      </html>
    `;

    await emailTransporter.sendMail({
      from: `"Manga AI Studio" <${process.env.SMTP_FROM}>`,
      to: email,
      subject: "Your Manga AI Studio Subscription Has Been Canceled",
      html: html,
    });

    console.log(`Cancellation email sent to ${email}`);
  } catch (error) {
    console.error("Cancellation email error:", error);
  }
};

// Paddle Webhook Handler
app.post(
  "/webhook/paddle",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signatureHeader = req.headers["paddle-signature"];
      const rawBody = req.body.toString("utf8");
      const secretKey = process.env.PADDLE_NOTIFICATION_SECRET;

      if (!signatureHeader || !rawBody) {
        return res.status(400).json({ error: "Missing signature or body" });
      }

      const eventData = await paddle.webhooks.unmarshal(
        rawBody,
        secretKey,
        signatureHeader
      );

      console.log("✅ Webhook verified:", eventData.eventType);

      handleWebhookEvent(eventData);

      res.status(200).json({ received: true });
    } catch (error) {
      console.error("❌ Webhook error:", error.message);
      res.status(200).json({ error: "Webhook processing failed" });
    }
  }
);

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
    case "subscription.past_due":
      await handleSubscriptionPaymentFailed(event.data);
      break;
    case "transaction.completed":
      await handleTransactionCompleted(event.data);
      break;
    default:
      console.log("Unhandled event:", event.event_type);
  }
}

// Add this helper function to cancel previous subscriptions
async function cancelPreviousSubscriptions(customerEmail, newSubscriptionId) {
  try {
    // Find all active subscriptions for this customer
    const { data: existingLicenses, error } = await supabase
      .from("licenses")
      .select("*")
      .eq("customer_email", customerEmail)
      .eq("type", "subscription")
      .in("status", ["active", "trialing"])
      .neq("subscription_id", newSubscriptionId);

    if (error) throw error;

    if (existingLicenses && existingLicenses.length > 0) {
      console.log(
        `Found ${existingLicenses.length} existing subscriptions for ${customerEmail}`
      );

      for (const license of existingLicenses) {
        // Cancel the subscription via Paddle API
        if (license.subscription_id) {
          try {
            // Call Paddle API to cancel subscription
            const paddleResponse = await fetch(
              `https://api.paddle.com/subscriptions/${license.subscription_id}/cancel`,
              {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${process.env.PADDLE_API_KEY}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  effective_from: "immediately",
                }),
              }
            );

            if (paddleResponse.ok) {
              console.log(
                `Cancelled Paddle subscription: ${license.subscription_id}`
              );
            }
          } catch (paddleError) {
            console.error(
              `Failed to cancel Paddle subscription ${license.subscription_id}:`,
              paddleError
            );
          }
        }

        // Update license status in database
        await supabase
          .from("licenses")
          .update({
            status: "canceled",
            canceled_at: new Date().toISOString(),
          })
          .eq("id", license.id);

        // Deactivate all devices for this license
        await supabase
          .from("activations")
          .update({
            is_active: false,
            deactivated_at: new Date().toISOString(),
          })
          .eq("license_id", license.id);

        console.log(`Canceled license ${license.id} for ${customerEmail}`);
      }
    }
  } catch (error) {
    console.error("Error canceling previous subscriptions:", error);
    // Don't throw - allow new subscription to proceed even if cancellation fails
  }
}
function safeDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d.toISOString();
}
async function handleSubscriptionCreated(subscription) {
  try {
    // Cancel any existing active subscriptions for this customer
    await cancelPreviousSubscriptions(
      subscription.customer_email,
      subscription.id
    );

    const isTrial = subscription.status === "trialing";

    const expiresAt = isTrial
      ? safeDate(subscription.trial_ends_at)
      : safeDate(subscription.next_billed_at);

    const licenseKey = await createLicense({
      type: "subscription",
      customerEmail: subscription.customer_email,
      customerName: subscription.customer_name,
      subscriptionId: subscription.id,
      expiresAt: expiresAt, // now safe (may be null)
      maxActivations: 3,
      isTrial: isTrial,
      status: "active",
    });

    console.log(
      `✅ Subscription license created for ${subscription.customer_email}`
    );
  } catch (error) {
    console.error("❌ Subscription created error:", error);
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

      // safely update expires_at if present
      const nextBilling = safeDate(subscription.next_billed_at);
      if (nextBilling) {
        updates.expires_at = nextBilling;
      }

      await supabase.from("licenses").update(updates).eq("id", license.id);
    }
  } catch (error) {
    console.error("❌ Subscription updated error:", error);
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

    console.log(`⚠️ Subscription canceled for ${subscription.customer_email}`);
  } catch (error) {
    console.error("❌ Subscription canceled error:", error);
  }
}

async function handleSubscriptionPaymentFailed(subscription) {
  try {
    await supabase
      .from("licenses")
      .update({ status: "past_due" })
      .eq("subscription_id", subscription.id);

    console.log(`⚠️ Payment failed for ${subscription.customer_email}`);
  } catch (error) {
    console.error("❌ Subscription payment failed error:", error);
  }
}

async function handleTransactionCompleted(transaction) {
  try {
    if (transaction.type === "one_time") {
      const licenseKey = await createLicense({
        type: "one_time",
        customerEmail: transaction.customer_email,
        customerName: transaction.customer_name,
        transactionId: transaction.id,
        maxActivations: 1,
        status: "active",
      });

      console.log(
        `✅ One-time license created for ${transaction.customer_email}`
      );
    }
  } catch (error) {
    console.error("❌ Transaction completed error:", error);
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
