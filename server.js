import { createClient } from "@supabase/supabase-js";
import cors from "cors";
import crypto, { createHmac, timingSafeEqual } from "crypto";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import nodemailer from "nodemailer";

// Load env vars
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const paddleUrl = process.env.PADDLE_URL || "https://sandbox-api.paddle.com";

// Initialize Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Email transporter
const emailTransporter = nodemailer.createTransport({
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
      "http://localhost:9002",
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

// Paddle Webhook Handler
app.post(
  "/webhook/paddle",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      if (!Buffer.isBuffer(req.body)) {
        console.error("Request body is not a buffer", req.body);
        return res.status(500).json({ error: "Server misconfigured" });
      }

      // 1. Get Paddle-Signature header
      const paddleSignature = req.headers["paddle-signature"];
      const secretKey = process.env.PADDLE_NOTIFICATION_SECRET;

      if (!paddleSignature) {
        console.error("Paddle-Signature not present in request headers");
        return res.status(400).json({ error: "Invalid request" });
      }

      if (!secretKey) {
        console.error("Secret key not defined");
        return res.status(500).json({ error: "Server misconfigured" });
      }

      // 2. Extract timestamp and signature from header
      if (!paddleSignature.includes(";")) {
        console.error("Invalid Paddle-Signature format");
        return res.status(400).json({ error: "Invalid request" });
      }

      const parts = paddleSignature.split(";");
      if (parts.length !== 2) {
        console.error("Invalid Paddle-Signature format");
        return res.status(400).json({ error: "Invalid request" });
      }

      const [timestampPart, signaturePart] = parts.map(
        (part) => part.split("=")[1]
      );

      if (!timestampPart || !signaturePart) {
        console.error(
          "Unable to extract timestamp or signature from Paddle-Signature header"
        );
        return res.status(400).json({ error: "Invalid request" });
      }

      const timestamp = timestampPart;
      const signature = signaturePart;

      // 3. Check timestamp (optional but recommended)
      const timestampInt = parseInt(timestamp) * 1000;
      if (isNaN(timestampInt)) {
        console.error("Invalid timestamp format");
        return res.status(400).json({ error: "Invalid request" });
      }

      const currentTime = Date.now();
      if (currentTime - timestampInt > 5000) {
        console.error(
          "Webhook event expired (timestamp is over 5 seconds old):",
          timestampInt,
          currentTime
        );
        return res.status(408).json({ error: "Event expired" });
      }

      // 4. Build signed payload
      const bodyRaw = req.body.toString();
      const signedPayload = `${timestamp}:${bodyRaw}`;

      // 5. Hash signed payload using HMAC SHA256
      const hashedPayload = createHmac("sha256", secretKey)
        .update(signedPayload, "utf8")
        .digest("hex");

      // 6. Compare signatures
      if (
        !timingSafeEqual(Buffer.from(hashedPayload), Buffer.from(signature))
      ) {
        console.error("Computed signature does not match Paddle signature");
        return res.status(401).json({ error: "Invalid signature" });
      }

      // 7. Process the webhook event
      const event = JSON.parse(bodyRaw);
      await handleWebhookEvent(event);

      res.status(200).json({ received: true });
    } catch (error) {
      console.error("Failed to verify and process Paddle webhook:", error);
      res.status(500).json({
        error: "Failed to verify and process Paddle webhook",
      });
    }
  }
);

app.use(express.json());

// License Key Generation
const generateLicenseKey = () => {
  const characters = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const segments = 4;
  const segmentLength = 4;

  let key = "";

  for (let i = 0; i < segments; i++) {
    for (let j = 0; j < segmentLength; j++) {
      const randomIndex = crypto.randomInt(0, characters.length);
      key += characters[randomIndex];
    }
    if (i < segments - 1) {
      key += "-";
    }
  }

  return key;
};

const hashLicenseKey = (licenseKey) => {
  return crypto.createHash("sha256").update(licenseKey).digest("hex");
};

const sendLicenseEmail = async (
  email,
  licenseKey,
  isTrial = false,
  customerName = "",
  trialEndDate = null
) => {
  try {
    const subject = isTrial
      ? "Your Manga AI Studio 7-Day Free Trial License"
      : "Your Manga AI Studio License";

    const trialText = isTrial
      ? `
      <p>Your <strong>7-day free trial</strong> has been activated. After the trial period, 
      your subscription will automatically continue unless canceled.</p>
      <p><strong>Trial End Date:</strong> ${
        trialEndDate
          ? new Date(trialEndDate).toLocaleDateString()
          : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toLocaleDateString()
      }</p>
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
          .license-key { font-size: 24px; font-weight: bold; letter-spacing: 2px; color: #007bff; }
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
            <div class="license-key">${licenseKey}</div>
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

// Helper function to get customer email from Paddle
const getCustomerEmail = async (customerId) => {
  try {
    console.log(`${paddleUrl}/customers/${customerId}`);
    const response = await fetch(`${paddleUrl}/customers/${customerId}`, {
      headers: {
        Authorization: `Bearer ${process.env.PADDLE_API_KEY}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch customer: ${response.statusText}`);
    }

    const data = await response.json();
    return data.data?.email || null;
  } catch (error) {
    console.error("Error fetching customer email:", error);
    return null;
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

    // Normalize license key (remove spaces, convert to uppercase)
    const normalizedKey = licenseKey.replace(/\s/g, "").toUpperCase();

    // Get license from database using hashed key
    const keyHash = hashLicenseKey(normalizedKey);

    const { data: license, error: licenseError } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key_hash", keyHash)
      .single();

    if (licenseError || !license) {
      return res.status(404).json({
        success: false,
        error: "Invalid license key",
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

    // Normalize license key
    const normalizedKey = licenseKey.replace(/\s/g, "").toUpperCase();
    const keyHash = hashLicenseKey(normalizedKey);

    // Get license from database
    const { data: license, error: licenseError } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key_hash", keyHash)
      .single();

    if (licenseError || !license) {
      return res.status(404).json({
        success: false,
        error: "Invalid license key",
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

    const normalizedKey = licenseKey.replace(/\s/g, "").toUpperCase();
    const keyHash = hashLicenseKey(normalizedKey);

    const { data: license } = await supabase
      .from("licenses")
      .select("id")
      .eq("license_key_hash", keyHash)
      .single();

    if (!license) {
      return res.status(404).json({
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
      .eq("license_id", license.id)
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

    const normalizedKey = licenseKey.replace(/\s/g, "").toUpperCase();
    const keyHash = hashLicenseKey(normalizedKey);

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
      .eq("license_key_hash", keyHash)
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

    const normalizedKey = licenseKey.replace(/\s/g, "").toUpperCase();
    const keyHash = hashLicenseKey(normalizedKey);

    // Get license from database
    const { data: license, error: licenseError } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key_hash", keyHash)
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
        `${paddleUrl}/subscriptions/${license.subscription_id}/cancel`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.PADDLE_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            effective_from: "next_billing_period",
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

// Webhook Event Handler
async function handleWebhookEvent(event) {
  console.log(
    "📥 Received webhook event:",
    event.event_type,
    "ID:",
    event.event_id
  );

  try {
    switch (event.event_type) {
      case "subscription.created":
        await handleSubscriptionCreated(event.data);
        break;

      case "subscription.updated":
        await handleSubscriptionUpdated(event.data);
        break;

      case "subscription.activated":
        await handleSubscriptionActivated(event.data);
        break;

      case "subscription.trialing":
        await handleSubscriptionTrialing(event.data);
        break;

      case "subscription.canceled":
        await handleSubscriptionCanceled(event.data);
        break;

      case "subscription.past_due":
        await handleSubscriptionPastDue(event.data);
        break;

      case "subscription.paused":
        await handleSubscriptionPaused(event.data);
        break;

      case "subscription.resumed":
        await handleSubscriptionResumed(event.data);
        break;

      case "transaction.completed":
        await handleTransactionCompleted(event.data);
        break;

      case "transaction.paid":
        await handleTransactionPaid(event.data);
        break;

      default:
        console.log("⚠️ Unhandled event type:", event.event_type);
    }
  } catch (error) {
    console.error(`❌ Error handling ${event.event_type}:`, error);
    throw error;
  }
}

async function handleSubscriptionCreated(subscription) {
  try {
    console.log("🆕 Processing subscription.created:", subscription.id);

    const customerEmail = await getCustomerEmail(subscription.customer_id);
    if (!customerEmail) {
      console.error("Could not fetch customer email");
      return;
    }

    await cancelPreviousSubscriptions(customerEmail, subscription.id);

    const isTrial = subscription.status === "trialing";
    const expiresAt = isTrial
      ? subscription.current_billing_period?.ends_at
      : subscription.next_billed_at;

    await createLicense({
      type: "subscription",
      customerEmail: customerEmail,
      customerName: "",
      subscriptionId: subscription.id,
      expiresAt: expiresAt,
      maxActivations: 3,
      isTrial: isTrial,
      status: subscription.status,
    });

    console.log(`✅ Subscription license created for ${customerEmail}`);
  } catch (error) {
    console.error("❌ Subscription created error:", error);
  }
}

async function handleSubscriptionUpdated(subscription) {
  try {
    console.log("🔄 Processing subscription.updated:", subscription.id);

    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (!license) {
      console.log("⚠️ License not found for subscription:", subscription.id);
      return;
    }

    const updates = {
      status: subscription.status,
    };

    if (
      subscription.scheduled_change &&
      subscription.scheduled_change.action === "cancel"
    ) {
      console.log(
        "⏰ Subscription has scheduled cancellation:",
        subscription.scheduled_change.effective_at
      );
      updates.scheduled_cancel_at = subscription.scheduled_change.effective_at;
    }

    if (subscription.next_billed_at) {
      updates.expires_at = subscription.next_billed_at;
    } else if (subscription.current_billing_period?.ends_at) {
      updates.expires_at = subscription.current_billing_period.ends_at;
    }

    await supabase.from("licenses").update(updates).eq("id", license.id);

    console.log(
      `✅ License updated for subscription ${subscription.id}, status: ${subscription.status}`
    );
  } catch (error) {
    console.error("❌ Subscription updated error:", error);
  }
}

async function handleSubscriptionActivated(subscription) {
  try {
    console.log("✅ Processing subscription.activated:", subscription.id);

    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (license) {
      await supabase
        .from("licenses")
        .update({
          status: "active",
          expires_at: subscription.next_billed_at,
        })
        .eq("id", license.id);

      console.log(`✅ License activated for subscription ${subscription.id}`);
    }
  } catch (error) {
    console.error("❌ Subscription activated error:", error);
  }
}

async function handleSubscriptionTrialing(subscription) {
  try {
    console.log("🧪 Processing subscription.trialing:", subscription.id);

    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (license) {
      await supabase
        .from("licenses")
        .update({
          status: "trialing",
          expires_at: subscription.current_billing_period?.ends_at,
        })
        .eq("id", license.id);

      console.log(
        `✅ License set to trialing for subscription ${subscription.id}`
      );
    }
  } catch (error) {
    console.error("❌ Subscription trialing error:", error);
  }
}

async function handleSubscriptionCanceled(subscription) {
  try {
    console.log("❌ Processing subscription.canceled:", subscription.id);

    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (license) {
      await supabase
        .from("licenses")
        .update({
          status: "canceled",
          canceled_at: subscription.canceled_at || new Date().toISOString(),
        })
        .eq("id", license.id);

      await supabase
        .from("activations")
        .update({
          is_active: false,
          deactivated_at: new Date().toISOString(),
        })
        .eq("license_id", license.id);

      console.log(`✅ Subscription canceled for ${license.customer_email}`);
    }
  } catch (error) {
    console.error("❌ Subscription canceled error:", error);
  }
}

async function handleSubscriptionPastDue(subscription) {
  try {
    console.log("⚠️ Processing subscription.past_due:", subscription.id);

    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (license) {
      await supabase
        .from("licenses")
        .update({ status: "past_due" })
        .eq("id", license.id);

      console.log(`⚠️ Payment failed for ${license.customer_email}`);
    }
  } catch (error) {
    console.error("❌ Subscription past_due error:", error);
  }
}

async function handleSubscriptionPaused(subscription) {
  try {
    console.log("⏸️ Processing subscription.paused:", subscription.id);

    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (license) {
      await supabase
        .from("licenses")
        .update({
          status: "paused",
          paused_at: subscription.paused_at || new Date().toISOString(),
        })
        .eq("id", license.id);

      console.log(`⏸️ Subscription paused for ${license.customer_email}`);
    }
  } catch (error) {
    console.error("❌ Subscription paused error:", error);
  }
}

async function handleSubscriptionResumed(subscription) {
  try {
    console.log("▶️ Processing subscription.resumed:", subscription.id);

    const { data: license } = await supabase
      .from("licenses")
      .select("*")
      .eq("subscription_id", subscription.id)
      .single();

    if (license) {
      await supabase
        .from("licenses")
        .update({
          status: "active",
          paused_at: null,
        })
        .eq("id", license.id);

      console.log(`▶️ Subscription resumed for ${license.customer_email}`);
    }
  } catch (error) {
    console.error("❌ Subscription resumed error:", error);
  }
}

async function handleTransactionCompleted(transaction) {
  try {
    console.log("💳 Processing transaction.completed:", transaction.id);

    if (transaction.billing_period === null) {
      const customerEmail = await getCustomerEmail(transaction.customer_id);
      if (!customerEmail) {
        console.error("Could not fetch customer email");
        return;
      }

      await createLicense({
        type: "one_time",
        customerEmail: customerEmail,
        customerName: "",
        transactionId: transaction.id,
        maxActivations: 1,
        status: "active",
      });

      console.log(`✅ One-time license created for ${customerEmail}`);
    }
  } catch (error) {
    console.error("❌ Transaction completed error:", error);
  }
}

async function handleTransactionPaid(transaction) {
  try {
    console.log("💰 Processing transaction.paid:", transaction.id);
  } catch (error) {
    console.error("❌ Transaction paid error:", error);
  }
}

async function createLicense({
  type,
  customerEmail,
  customerName,
  transactionId = null,
  subscriptionId = null,
  expiresAt = null,
  maxActivations,
  isTrial = false,
  status = "active",
}) {
  // Generate short license key
  const licenseKey = generateLicenseKey();
  const licenseKeyHash = hashLicenseKey(licenseKey);

  const { data: license, error } = await supabase
    .from("licenses")
    .insert([
      {
        type,
        status,
        customer_email: customerEmail,
        transaction_id: transactionId,
        subscription_id: subscriptionId,
        expires_at: expiresAt,
        max_activations: maxActivations,
        is_trial: isTrial,
        license_key_hash: licenseKeyHash,
        created_at: new Date().toISOString(),
      },
    ])
    .select()
    .single();

  if (error) throw error;

  // Send email with license key
  await sendLicenseEmail(
    customerEmail,
    licenseKey,
    isTrial,
    customerName,
    expiresAt
  );

  return licenseKey;
}

async function cancelPreviousSubscriptions(customerEmail, newSubscriptionId) {
  try {
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
        if (license.subscription_id) {
          try {
            const paddleResponse = await fetch(
              `${paddleUrl}/subscriptions/${license.subscription_id}/cancel`,
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

        await supabase
          .from("licenses")
          .update({
            status: "canceled",
            canceled_at: new Date().toISOString(),
          })
          .eq("id", license.id);

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
  }
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
