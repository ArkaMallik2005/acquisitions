import { jest } from "@jest/globals";
import request from "supertest";

await jest.unstable_mockModule(
  "../src/middleware/security.middleware.js",
  () => ({
    default: (req, res, next) => next(),
  }),
);

const { default: app } = await import("../src/app.js");

describe("API Endpoints", () => {
  describe("GET /health", () => {
    it("should return status ok", async () => {
      const res = await request(app).get("/health");
      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("status", "ok");
      expect(res.body).toHaveProperty("timestamp");
      expect(res.body).toHaveProperty("uptime");
    });
  });

  describe("GET /api", () => {
    it("should return welcome message", async () => {
      const res = await request(app).get("/api");
      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("message", "Welcome to the API!");
    });
  });

  describe("GET /nonexistent", () => {
    it("should return 404 for nonexistent routes", async () => {
      const res = await request(app).get("/nonexistent");
      expect(res.statusCode).toEqual(404);
      expect(res.body).toHaveProperty("error");
    });
  });
});
