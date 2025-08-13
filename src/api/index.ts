import { Router } from 'express';
import v1Router from './v1';

const router = Router();

// API versions
router.use('/v1', v1Router);

// Future versions can be added here
// router.use('/v2', v2Router);

export default router;
