const { create } = require('connect-mongo');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('./models');

passport.use('signup', new LocalStrategy({
    passReqToCallback: true
}, (req, username, password, done) => {
    User.findOne({ username }, (err, user) => {
        if (err) {
            return done(err);
        }

        if (user) {
            return done(null, false, { message: 'El usuario ya existe' });
        }

        const newUser = new User({
            username: username,
            password: createHash(password),
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName
        });

        newUser.save((err) => {
            if (err) {
                return done(err);
            }

            return done(null, newUser);
        });
    });
}  
));

const createHash = (password) => {
    return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
}

passport.use('login', new LocalStrategy({
    passReqToCallback: true
}, (req, username, password, done) => {
    User.findOne({ username }, (err, user) => {
        if (err) {
            return done(err);
        }

        if (!user) {
            return done(null, false, { message: 'El usuario no existe' });
        }

        if (!isValidPassword(user, password)) {
            return done(null, false, { message: 'Contraseña incorrecta' });
        }

        return done(null, user);
    });
}));

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});