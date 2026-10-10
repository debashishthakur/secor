exports.requireAuth = (req, res, next) => (req.user ? next() : res.sendStatus(401));
