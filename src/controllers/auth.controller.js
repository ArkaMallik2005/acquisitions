import logger from "../config/logger.js";
import { createUser, authenticateUser } from "../services/auth.service.js";
import { signUpSchema } from "../validations/auth.validation.js";
import { jwttoken } from "../utils/jwt.js";
import { cookies } from "../utils/cookies.js";

// 🔐 SIGNUP
export const signup = async (req, res, next) => {
  try {
    const validationResult = signUpSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: "Validation failed",
        details: validationResult.error.issues,
      });
    }

    const { name, email, password, role } = validationResult.data;

    const user = await createUser({ name, email, password, role });

    const token = jwttoken.sign({
      userId: user.id,
      role: user.role,
      email: user.email,
    });

    cookies.set(res, "token", token);

    logger.info(`User ${email} signed up successfully`);

    return res.status(201).json({
      message: "User signed up successfully",
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });

  } catch (error) {
    logger.error("Error in signup controller:", error);

    if (error.message === "user with email already exists") {
      return res.status(409).json({
        error: "User with this email already exists",
      });
    }

    next(error);
  }
};

// 🔑 LOGIN
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const user = await authenticateUser({ email, password });

    const token = jwttoken.sign({
      userId: user.id,
      role: user.role,
      email: user.email,
    });

    cookies.set(res, "token", token);

    logger.info(`User ${email} logged in successfully`);

    return res.status(200).json({
      message: "Login successful",
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });

  } catch (error) {
    logger.error("Error in login controller:", error);

    return res.status(401).json({
      error: "Invalid email or password",
    });
  }
};