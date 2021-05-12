const bcrypt = require('bcryptjs')

module.exports = {
    register: async (req, res) => {
        const db = req.app.get('db')
        const {email, password} = req.body
        const foundUser = await db.check_user_exists(email)
        if(foundUser[0]) {
            return res.status(409).send('sorry, that email is already in use')
        }
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const createdUser = await db.create_user(email, hash)
        delete createdUser[0].user_password
        req.session.user = createdUser[0]
        res.status(200).send(req.session.user)
    },
    login: async (req, res) => {
        const db = req.app.get('db')
        const {email, password} = req.body
        const foundUser = await db.check_user_exists(email)
        if(!foundUser[0]) {
            return res.status(401).send('email or password incorrect :(')
        }
        const result = bcrypt.compareSync(password, foundUser[0].user_password)
        if(result) {
            delete foundUser[0].user_password
            req.session.user = foundUser[0]
            return res.status(200).send(req.session.user)
        }
        return res.status(401).send('email or password incorrect :(')
    },
    logout: (req, res) => {
        req.session.destroy()
        res.sendStatus(200)
    }
}