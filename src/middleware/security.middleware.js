import aj from "../config/arcjet.js";
import logger from "#config/logger.js";
import { slidingWindow } from "@arcjet/node";


const securityMiddleware = async (req, res, next) => {
    try {
        if (req.path === "/health") {
        return next();
}
        const role = req.user?.role || "GUEST"; // Default to GUEST if no user role is found

        let limit;
        let message;

        switch (role) {
            case "ADMIN":
                limit = 20;
                message = "Admin rate limit exceeded.(20 per minute). Slow down.";
                break;
            case "USER":
                limit = 10;
                message = "User rate limit exceeded.(10 per minute). Slow down.";
                break;
            case "GUEST":
                limit = 5;
                message = "Guest rate limit exceeded.(5 per minute). Slow down.";
                break;

        }
          const decision = await aj.protect(req);
          

          if(decision.isDenied() && decision.reason.isBot()){ 
            logger.warn(`Blocked bot request; ip: ${req.ip}, path: ${req.path}, userAgent: ${req.get("User-Agent")}`);
            return res.status(403).json({ message: "Access denied. Bot traffic is not allowed." });
          }

          if(decision.isDenied() && decision.reason.isShield()){ 
            logger.warn(`Shield blocked request; ip: ${req.ip}, path: ${req.path}, userAgent: ${req.get("User-Agent")}, method: ${req.method}`);
            return res.status(403).json({ message: "Access denied. Request blocked by shield." });
          }

          if(decision.isDenied() && decision.reason.isRateLimit()){ 
                logger.warn(`Rate limit exceeded request; ip: ${req.ip}, path: ${req.path}, userAgent: ${req.get("User-Agent")}, method: ${req.method}`);
                return res.status(429).json({ message: "Too many requests. Please try again later." });
              }
    
            next();
        } catch (error) {
            console.error("Error in security middleware:", error);
            return res.status(500).json({ message: "Internal server error" });
        }
    }
    
    export default securityMiddleware;