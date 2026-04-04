import authenticate from "../middleware/authMiddleware.js";
import express from "express";
import {
  createCase,
  getAllCases,
  getCaseById,
  updateCaseStatus,
  deleteCase,
  assignUserToCase,
  getCaseUsers,
  removeUserFromCase,
} from "../controllers/caseController.js";

const router = express.Router();

// Case CRUD
router.post("/", authenticate, createCase);
router.get("/", authenticate, getAllCases);
router.get("/:id", authenticate, getCaseById);
router.put("/:id/status", authenticate, updateCaseStatus);
router.delete("/:id", authenticate, deleteCase);

// Case Users management
router.post("/:id/users", authenticate, assignUserToCase);
router.get("/:id/users", authenticate, getCaseUsers);
router.delete("/:id/users/:userId", authenticate, removeUserFromCase);

export default router;