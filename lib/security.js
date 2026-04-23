const crypto = require("crypto");

function ensureCsrfToken(req, _res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return next();
}

function renderWithCsrf(view) {
  return (req, res) => {
    res.render(view, { csrfToken: req.session.csrfToken });
  };
}

function requireCsrf(req, res, next) {
  const token =
    req.headers["x-csrf-token"] ||
    req.headers["x-xsrf-token"] ||
    (req.body && req.body._csrf);

  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send("Invalid CSRF token");
  }
  return next();
}

function requireLogin(absUrl) {
  return function 로그인(req, res, next) {
    if (req.isAuthenticated?.() || req.session.user) {
      return next();
    }
    req.flash("error", "로그인이 필요합니다.");
    return res.redirect(absUrl("/login"));
  };
}

module.exports = {
  ensureCsrfToken,
  renderWithCsrf,
  requireCsrf,
  requireLogin,
};
