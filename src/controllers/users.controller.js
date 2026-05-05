import logger from '../config/logger.js';
import {
  getAllUsers,
  getUserById as getUserByIdService,
  updateUser as updateUserService,
  deleteUser as deleteUserService,
} from '../services/users.service.js';
import {
  updateUserSchema,
  userIdSchema,
} from '../validations/users.validation.js';
export const fetchAllUsers = async (req, res, next) => {
  try {
    logger.info('Getting users...');

    const allUsers = await getAllUsers();

    res.json({
      message: 'Users fetched successfully',
      users: allUsers,
      count: allUsers.length,
    });
  } catch (error) {
    logger.error('Error in getUsers controller', {
      error: error.message,
      stack: error.stack,
    });
    next(error);
  }
};

export const getUserById = async (req, res, next) => {
  try {
    const parsedParams = userIdSchema.safeParse(req.params);

    if (!parsedParams.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: parsedParams.error.issues,
      });
    }

    const { id } = parsedParams.data;
    logger.info('Getting user by id...', { userId: id });

    const user = await getUserByIdService(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({
      message: 'User fetched successfully',
      user,
    });
  } catch (error) {
    logger.error('Error in getUserById controller', {
      error: error.message,
      stack: error.stack,
    });
    next(error);
  }
};

export const updateUser = async (req, res, next) => {
  try {
    const parsedParams = userIdSchema.safeParse(req.params);
    const parsedBody = updateUserSchema.safeParse(req.body);

    if (!parsedParams.success || !parsedBody.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: {
          params: parsedParams.success ? [] : parsedParams.error.issues,
          body: parsedBody.success ? [] : parsedBody.error.issues,
        },
      });
    }

    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const targetUserId = parsedParams.data.id;
    const updates = parsedBody.data;
    const requesterId = Number(req.user.userId ?? req.user.id);
    const requesterRole = String(req.user.role || '').toLowerCase();
    const isAdmin = requesterRole === 'admin';
    const isSelfUpdate = requesterId === targetUserId;

    if (!isAdmin && !isSelfUpdate) {
      return res
        .status(403)
        .json({ error: 'You can only update your own profile' });
    }

    if (updates.role && !isAdmin) {
      return res
        .status(403)
        .json({ error: 'Only admin users can update user roles' });
    }

    logger.info('Updating user...', {
      targetUserId,
      requesterId,
      requesterRole,
    });
    const updatedUser = await updateUserService(targetUserId, updates);

    return res.status(200).json({
      message: 'User updated successfully',
      user: updatedUser,
    });
  } catch (error) {
    if (error.status === 404) {
      return res.status(404).json({ error: error.message });
    }
    logger.error('Error in updateUser controller', {
      error: error.message,
      stack: error.stack,
    });
    next(error);
  }
};

export const deleteUser = async (req, res, next) => {
  try {
    const parsedParams = userIdSchema.safeParse(req.params);

    if (!parsedParams.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: parsedParams.error.issues,
      });
    }

    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const targetUserId = parsedParams.data.id;
    const requesterId = Number(req.user.userId ?? req.user.id);
    const requesterRole = String(req.user.role || '').toLowerCase();
    const isAdmin = requesterRole === 'admin';
    const isSelfDelete = requesterId === targetUserId;

    if (!isAdmin && !isSelfDelete) {
      return res
        .status(403)
        .json({ error: 'You can only delete your own account' });
    }

    logger.info('Deleting user...', {
      targetUserId,
      requesterId,
      requesterRole,
    });
    const deletedUser = await deleteUserService(targetUserId);

    return res.status(200).json({
      message: 'User deleted successfully',
      user: deletedUser,
    });
  } catch (error) {
    if (error.status === 404) {
      return res.status(404).json({ error: error.message });
    }
    logger.error('Error in deleteUser controller', {
      error: error.message,
      stack: error.stack,
    });
    next(error);
  }
};
