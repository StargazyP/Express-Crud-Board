const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local").Strategy;

function configurePassport(passport, getDb) {
  passport.use(
    new LocalStrategy(
      {
        usernameField: "id",
        passwordField: "pw",
        session: true,
      },
      (id, pw, done) => {
        const db = getDb();
        if (!db) return done(new Error("DB is not connected yet"));

        db.collection("login").findOne({ id }, async (err, user) => {
          if (err) return done(err);
          if (!user) {
            return done(null, false, {
              message: "존재하지 않는 아이디입니다.",
            });
          }

          try {
            const match = await bcrypt.compare(pw, user.pw);
            if (match) return done(null, user);
            return done(null, false, {
              message: "비밀번호가 일치하지 않습니다.",
            });
          } catch (error) {
            return done(error);
          }
        });
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user.id));

  passport.deserializeUser((id, done) => {
    const db = getDb();
    if (!db) return done(new Error("DB is not connected yet"));
    db.collection("login").findOne({ id }, (err, user) => done(err, user));
  });
}

module.exports = {
  configurePassport,
};
