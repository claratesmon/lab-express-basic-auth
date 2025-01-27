const { Router } = require('express'); //Router is part of EXPRESS  (why curly braces {}?)
const router = new Router();
const User = require("../models/User.model")

const bcrypt = require('bcryptjs');
const saltRounds = 5;
const mongoose = require('mongoose')

// require auth middleware
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard');


router.get('/signup', isLoggedOut, (req, res) => {
    res.render('auth/signup')
})

router.get('/profilePage', isLoggedIn, (req, res) => {
    res.render('profilePage', { userInSession: req.session.currentUser });

})

router.get('/main', isLoggedIn, (req, res) => {
    res.render('auth/main')

})

router.get('/private', isLoggedIn, (req, res) => {
    res.render('auth/private');

})

router.post('/signup', (req, res, next) => {
    const { username, password } = req.body

    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
        res.status(500).render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, username and password.' });
        return
    }

    bcrypt.genSalt(saltRounds)
        .then(salt => bcrypt.hash(password, salt))
        .then((hashedPassword) => {
            //console.log({ hashedPassword });
            User.create({
                username,
                password: hashedPassword
            })

        })
        .then((userCreated) => {
            res.redirect('./profilePage')

        })

        //Since this validation is part of mongoose,
        // we will have to use mongoose to retrieve the message.
        .catch(error => {
            // copy the following if-else statement
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup', { errorMessage: error.message });
            } else {
                next(error);
            }
        })                                    //next(error) //goes to the next middleware

});

//////////// L O G I N ///////////

// GET login route stays unchanged
router.get('/login', isLoggedOut, (req, res) => {
    res.render('auth/login')
});

// POST login route ==> to process form data
router.post('/login', (req, res, next) => {

    const { username, password } = req.body;
    if (username === '' || password === '') {
        res.render('auth/login', {
            errorMessage: 'Please enter both, username and password to login.'
        });
        return;
    }

    User.findOne({ username })   ///remember it is a MongoDB method

        .then(user => {

            if (!user) {
                console.log("User not registered. ");
                res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
                return;
            } else if (bcrypt.compareSync(password, user.password)) {  ////password from DB, not user model
                req.session.currentUser = user
                console.log(req.session.currentUser)
                res.redirect('/profilePage');
            } else {
                console.log("Incorrect password.");
                res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
            }
        })
        .catch(error => next(error));
});

///LOGOUT
router.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) next(err);
        res.redirect('/');
    });
})



module.exports = router;