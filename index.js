const express = require("express");
const passport = require('passport');
const boom = require('@hapi/boom');
const cookieParser = require('cookie-parser');
const axios = require('axios');

const { config } = require("./config");

const app = express();

// body parser
app.use(express.json());
app.use(cookieParser());

// Basic strategy
require('./utils/auth/strategies/basic')

const THIRTY_DAYS_IN_SEC = 2592000000;
const TWO_HOURS_IN_SEC = 7200000;

app.post("/auth/sign-in", async (req, res, next) => {

  const { rememberMe } = req.body;

  passport.authenticate('basic', (error,data) => {
    try {
      if(error || !data) {
        next(boom.unauthorized());
      }

      req.login(data, { session: false }, async (error) => {
        if(error) {
          next(error);
        }

        const { token, ...user } = data;

        res.cookie('token', token, {
          httpOnly: !config.dev,
          secure: !config.dev,
          maxAge: rememberMe ? THIRTY_DAYS_IN_SEC : TWO_HOURS_IN_SEC
        });

        res.status(200).json(user);
      });
    } catch (error) {
      next(error);
    }
  });
});

app.post("/auth/sign-up", async function(req, res, next) {
  const { body: user } = req;

  try {
    await axios({
      url: `${config.apiUrl}/api/auth/sign-up`,
      method: 'post',
      data: user
    });

    res.status(201).json({ message: 'user created' });
  } catch (error) {
    next(error);
  }
});

app.get("/movies", async function(req, res, next) {

});

app.post("/user-movies", async function(req, res, next) {

});

app.delete("/user-movies/:userMovieId", async function(req, res, next) {

});

app.listen(config.port, function() {
  console.log(`Listening http://localhost:${config.port}`);
});
