const express = require("express");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3001;
const API_BASE_URL =
  process.env.API_BASE_URL || "https://hngstage3.onrender.com";

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: false,
  }),
);
app.use(
  cors({
    origin: [API_BASE_URL, "http://localhost:3000", "http://localhost:3001"],
    credentials: true,
  }),
);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// CSRF protection
const csrfProtection = csrf({ cookie: true });

// Middleware to check authentication
app.use(async (req, res, next) => {
  const accessToken = req.cookies?.access_token;
  // Only verify token for protected routes (not static files or auth endpoints)
  if (
    accessToken &&
    req.path !== "/login" &&
    req.path !== "/logout" &&
    !req.path.startsWith("/auth/") &&
    !req.path.startsWith("/api/") &&
    !req.path.match(/\.(css|js|png|jpg|gif|ico)$/)
  ) {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/profiles?limit=1`, {
        headers: {
          "X-API-Version": "1",
          Authorization: `Bearer ${accessToken}`,
        },
        timeout: 5000, // 5 second timeout
      });
      res.locals.authenticated = true;
      console.log("✅ Token verified");
    } catch (error) {
      console.log("⚠️ Token verification failed:", error.message);
      res.locals.authenticated = false;
    }
  } else {
    res.locals.authenticated = !!accessToken; // Simple check: if token exists, assume authenticated
  }
  next();
});

// Routes
app.get("/", (req, res) => {
  if (res.locals.authenticated) {
    res.redirect("/dashboard");
  } else {
    res.sendFile(path.join(__dirname, "public", "login.html"));
  }
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// OAuth callback handler - THIS IS CRITICAL
app.get("/auth/github/callback", async (req, res) => {
  const { code, state, error } = req.query;

  console.log("📥 Frontend callback received");
  console.log("Code:", code ? "Yes" : "No");
  console.log("State:", state);
  console.log("Error:", error);

  if (error) {
    console.error("❌ GitHub OAuth error:", error);
    return res.redirect("/login?error=oauth_failed");
  }

  if (!code) {
    console.error("❌ No code provided");
    return res.redirect("/login?error=no_code");
  }

  try {
    console.log(
      "🔄 Forwarding to backend at:",
      `${API_BASE_URL}/auth/github/callback`,
    );

    const backendCallbackUrl = `${API_BASE_URL}/auth/github/callback?code=${encodeURIComponent(code)}${state ? `&state=${encodeURIComponent(state)}` : ""}`;
    console.log("📍 Full URL:", backendCallbackUrl);

    const response = await axios.get(backendCallbackUrl, {
      maxRedirects: 0,
      validateStatus: () => true, // Accept all status codes
    });

    console.log("✅ Backend response received");
    console.log("Status:", response.status);
    console.log("Status Text:", response.statusText);
    console.log("Headers location:", response.headers.location);
    console.log("Response body:", response.data);

    // Handle redirects from backend
    if (response.status >= 300 && response.status < 400) {
      const redirectLocation = response.headers.location;
      console.log(
        `🔄 Backend returned ${response.status} redirect to:`,
        redirectLocation,
      );

      // Forward cookies
      if (response.headers["set-cookie"]) {
        console.log("🍪 Setting cookies from backend");
        response.headers["set-cookie"].forEach((cookie) => {
          res.setHeader("Set-Cookie", cookie);
        });
      }

      // If backend redirects to dashboard on frontend, follow it
      // Otherwise return as-is (for external redirects)
      console.log("➡️ Frontend redirecting to:", redirectLocation);
      return res.redirect(redirectLocation);
    }

    // Handle JSON responses (success)
    if (response.data && response.data.status === "success") {
      console.log("✅ Backend returned success JSON");

      // Forward cookies
      if (response.headers["set-cookie"]) {
        console.log("🍪 Setting cookies from backend");
        response.headers["set-cookie"].forEach((cookie) => {
          res.setHeader("Set-Cookie", cookie);
        });
      }

      // Redirect to dashboard
      console.log("➡️ Redirecting to dashboard");
      return res.redirect("/dashboard");
    }

    // Handle error responses
    if (response.data && response.data.status === "error") {
      console.error("❌ Backend error:", response.data.message);
      return res.redirect(
        `/login?error=${encodeURIComponent(response.data.message)}`,
      );
    }

    // Fallback
    console.log("⚠️ Unexpected backend response");
    res.redirect("/dashboard");
  } catch (error) {
    console.error("❌ Frontend callback error:", error.message);
    if (error.response) {
      console.error("Response status:", error.response.status);
      console.error("Response data:", error.response.data);
    }
    res.redirect("/login?error=authentication_failed");
  }
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/profiles", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profiles.html"));
});

app.get("/profile-detail", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile-detail.html"));
});

app.get("/search", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "search.html"));
});

app.get("/account", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "account.html"));
});

app.get("/logout", (req, res) => {
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.redirect("/login");
});

app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Start server
app.listen(PORT, () => {
  console.log(
    `✅ Insighta Labs+ Web Portal running on http://localhost:${PORT}`,
  );
  console.log(`🔗 API Base URL: ${API_BASE_URL}`);
  console.log(`🌐 Open http://localhost:${PORT} in your browser`);
});
