 'use strict';
  
  const unleash = require('unleash-server');
  const passport = require('@passport-next/passport');
  const GoogleOAuth2Strategy = require('@passport-next/passport-google-oauth2');
  
  const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
  const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
  const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL;
  const sharedSecret = process.env.SHARED_SECRET;
  
  passport.use(
    new GoogleOAuth2Strategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL,
      },
      (accessToken, refreshToken, profile, cb) => {
        cb(
          null,
          new unleash.User({
            name: profile.displayName,
            email: profile.emails[0].value,
          }),
        );
      },
    ),
  );
  
  function googleAdminAuth(app) {
    app.use(passport.initialize());
    app.use(passport.session());
    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((user, done) => done(null, user));
  
    app.get(
      '/api/admin/login',
      passport.authenticate('google', { scope: ['email'] }),
    );
    app.get(
      '/api/auth/callback',
      passport.authenticate('google', {
        failureRedirect: '/api/admin/error-login',
      }),
      (req, res) => {
        res.redirect('/');
      },
    );
  
    app.use('/api/client', (req, res, next) => {
      if (req.header('authorization') !== sharedSecret) {
        res.sendStatus(401);
      } else {
        next();
      }
    });
    app.use('/api/admin/', (req, res, next) => {
      if (req.user) {
        next();
      } else {
        return res
          .status('401')
          .json(
            new unleash.AuthenticationRequired({
              path: '/api/admin/login',
              type: 'custom',
              message: `You have to identify yourself in order to use Unleash. Click the button and follow the instructions.`,
            }),
          )
          .end();
      }
    });
  }
  
  const options = {
    enableLegacyRoutes: false,
    adminAuthentication: 'custom',
    preRouterHook: googleAdminAuth,
  };
  
  unleash.start(options).then(instance => {
    console.log(
      `Unleash started on http://localhost:${instance.app.get('port')}`,
    );
  });
