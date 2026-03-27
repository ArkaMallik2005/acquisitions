import express from "express";
import { signup, login } from "../controllers/auth.controller.js";

const router = express.Router();

// 🔐 SIGNUP
router.post("/sign-up", signup);

// 🔑 LOGIN
router.post("/sign-in", login);

// 🚪 LOGOUT
router.post("/sign-out", (req, res) => {
  res.clearCookie("token");

  return res.status(200).json({
    message: "Logged out successfully",
  });
});

export default router;