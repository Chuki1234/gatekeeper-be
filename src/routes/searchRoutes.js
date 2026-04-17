const { Router } = require('express');
const { searchIntelligence } = require('../controllers/searchController');
const { scanLimiter } = require('../middleware/rateLimiter');

const router = Router();

router.get('/', scanLimiter, searchIntelligence);

module.exports = router;
