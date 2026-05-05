// import express from 'express';
// import { fetchAllUsers, getUserById, updateUser, deleteUser } from '../controllers/users.controller.js';
// import { authenticateToken } from '../middleware/auth.middleware.js';

// const router = express.Router();

// router.get('/', authenticateToken, fetchAllUsers);
// router.get('/:id', authenticateToken, fethUserById);
// router.put('/:id', authenticateToken,updateUser);
// router.delete('/:id', authenticateToken, requireRole(['admin']), deleteUserById);

// export default router;

import express from 'express';
import {
  fetchAllUsers,
  getUserById,
  updateUser,
  deleteUser,
} from '../controllers/users.controller.js';

const router = express.Router();

// Temporary: no auth middleware
router.get('/', fetchAllUsers);
router.get('/:id', getUserById);
router.put('/:id', updateUser);
router.delete('/:id', deleteUser);

export default router;
