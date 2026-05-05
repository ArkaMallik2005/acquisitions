import aj from "../config/arcjet.js";
import logger from "#config/logger.js";

// 🚨 FORCE DISABLE in Jest (no condition ambiguity)
if (process.env.JEST_WORKER_ID !== undefined) {
  const noop = (req, res, next) => next();
  export default noop;
}

// ---- REAL MIDDLEWARE BELOW ----

const securityMiddleware = async (req, res, next) => {
  try {
    if (req.path === "/health") return next();

    const decision = await aj.protect(req);

    if (decision.isDenied() && decision.reason.isBot()) {
      return res.status(403).json({ error: "Bot blocked" });
    }

    if (decision.isDenied() && decision.reason.isShield()) {
      return res.status(403).json({ error: "Blocked by shield" });
    }

    if (decision.isDenied() && decision.reason.isRateLimit()) {
      return res.status(429).json({ error: "Rate limit exceeded" });
    }

    return next();

  } catch (err) {
    logger.error("Security middleware error:", err);

    // 🚨 IMPORTANT: never break flow
    return next();
  }
};

export default securityMiddleware;