import { Router } from 'express';

const router = Router();

// Module routes will be mounted here
// router.use('/auth', authRoutes);
// router.use('/users', userRoutes);
// router.use('/products', productRoutes);

/**
 * @swagger
 * /:
 *   get:
 *     summary: API v1 information
 *     description: Get information about API version 1
 *     tags:
 *       - General
 *     responses:
 *       200:
 *         description: API information
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: API v1
 *                 version:
 *                   type: string
 *                   example: 1.0.0
 */
router.get('/', (req, res) => {
  res.json({
    message: 'API v1',
    version: '1.0.0',
  });
});

export default router;
