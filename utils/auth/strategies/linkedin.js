const passport = require('passport');
const axios = require('axios');
const boom = require('@hapi/boom');
const { Strategy: LinkedInStrategy } = require('passport-linkedin-oauth2');

const { config } = require('../../../config');

passport.use(
    new LinkedInStrategy({
        clientID: config.linkedinKey,
        clientSecret: config.linkedinSecret,
        callbackURL: "/auth/linkedin/callback",
        scope: ['r_emailaddress', 'r_liteprofile'],
    },
        async (token, tokenSecret, profile, cb) => {
            const { data, status } = await axios({
                url: `${config.apiUrl}/api/auth/sign-provider`,
                method: 'post',
                data: {
                    name: profile.displayName,
                    email: profile.emails[0].value,
                    password: profile.id,
                    apiKeyToken: config.apiKeyToken
                },
            });

            if (!data || status !== 200) {
                return cb(boom.unauthorized());
            }

            return cb(null, data);
        }
    )
);