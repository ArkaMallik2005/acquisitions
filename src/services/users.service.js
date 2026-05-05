import { eq } from 'drizzle-orm';
import logger from '../config/logger.js';
import { db } from '../config/database.js';
import { users } from '../models/users.model.js';

const userSelectProjection = {
  id: users.id,
  name: users.name,
  email: users.email,
  role: users.role,
  createdAt: users.created_at,
  updatedAt: users.updated_at,
};

export const getAllUsers = async () => {
  try {
    return await db.select(userSelectProjection).from(users);
  } catch (error) {
    logger.error('Error fetching users', {
      error: error.message,
      stack: error.stack,
    });
    throw new Error('Failed to fetch users');
  }
};

export const getUserById = async id => {
  try {
    const [user] = await db
      .select(userSelectProjection)
      .from(users)
      .where(eq(users.id, id))
      .limit(1);
    return user || null;
  } catch (error) {
    logger.error('Error fetching user by id', {
      error: error.message,
      stack: error.stack,
      userId: id,
    });
    throw new Error('Failed to fetch user');
  }
};

export const updateUser = async (id, updates) => {
  try {
    const existingUser = await getUserById(id);

    if (!existingUser) {
      const notFoundError = new Error('User not found');
      notFoundError.status = 404;
      throw notFoundError;
    }

    const [updatedUser] = await db
      .update(users)
      .set({
        ...updates,
        updated_at: new Date(),
      })
      .where(eq(users.id, id))
      .returning(userSelectProjection);

    return updatedUser;
  } catch (error) {
    if (error.status === 404) {
      throw error;
    }
    logger.error('Error updating user', {
      error: error.message,
      stack: error.stack,
      userId: id,
    });
    throw new Error('Failed to update user');
  }
};

export const deleteUser = async id => {
  try {
    const existingUser = await getUserById(id);

    if (!existingUser) {
      const notFoundError = new Error('User not found');
      notFoundError.status = 404;
      throw notFoundError;
    }

    const [deletedUser] = await db
      .delete(users)
      .where(eq(users.id, id))
      .returning(userSelectProjection);
    return deletedUser;
  } catch (error) {
    if (error.status === 404) {
      throw error;
    }
    logger.error('Error deleting user', {
      error: error.message,
      stack: error.stack,
      userId: id,
    });
    throw new Error('Failed to delete user');
  }
};
