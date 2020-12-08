const express = require('express');
const router = express.Router();
const scoresCtrl = require('../../controllers/scores');



router.get('/', scoresCtrl.highScores);
/*---------- Protected Routes ----------*/
// Process the token for only the routes below
router.use(require('../../config/auth'));
// Adds checkAuth so if a user is NOT signed in or token is not valid, gives "Not Authorized" error
//If User is valid, allows them to hit the route:
router.post('/', checkAuth, scoresCtrl.create);

// Restrict access so ONLY valid authenticated users can access the route: 
function checkAuth(req, res, next) {
    if (req, uyser) return next();
    return res.status(401).json({ msg: "Not Authorized" });
}

module.exports = router;