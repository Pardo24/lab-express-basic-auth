const router = require("express").Router();

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("../views/index.hbs");
});

module.exports = router;
