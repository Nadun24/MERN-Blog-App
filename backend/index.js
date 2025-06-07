const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')
const Post = require('./model/Post')
const bcrypt = require('bcryptjs')
const User = require('./model/User')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const multer = require('multer')
const uploadMiddleware = multer({ dest: 'upload/' })
const fs = require('fs')

const salt = bcrypt.genSaltSync(10)
const secret = 'abcdefghi'

const app = express()

app.use(cors({ credentials: true, origin: 'http://localhost:3000' }))
app.use(express.json())
app.use(cookieParser())
app.use('/upload', express.static(__dirname + '/upload'))

mongoose.connect('mongodb://localhost:27017', console.log('Database connected'))

function authenticateToken (req, res, next) {
  const token = req.cookies.token // Ensure the token is coming from the cookies
  if (!token) return res.status(401).json('No token provided')

  jwt.verify(token, secret, (err, user) => {
    if (err) return res.status(403).json('Invalid token')
    req.user = user // Assign the decoded user info to req.user
    next()
  })
}

app.post('/register', async (req, res) => {
  const { name, username, password } = req.body
  try {
    const userDoc = await User.create({
      name,
      username,
      password: bcrypt.hashSync(password, salt)
    })
    res.json(userDoc)
  } catch (e) {
    console.log(e)
    res.status(400).json(e)
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body

  const userDoc = await User.findOne({ username: username })

  if (!userDoc) {
    return res.status(400).json('User not found')
  }

  const passOk = bcrypt.compareSync(password, userDoc.password)

  if (passOk) {
    jwt.sign(
      { username, id: userDoc._id },
      secret,
      { expiresIn: '1h' },
      (err, token) => {
        if (err) throw err
        res.cookie('token', token, { httpOnly: true }).json({
          id: userDoc._id,
          username
        })
      }
    )
  } else {
    res.status(400).json('Wrong credentials')
  }
})

app.get('/profile', (req, res) => {
  const { token } = req.cookies
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) throw err
    res.json(info)
  })
})

app.post('/logout', (req, res) => {
  res.cookie('token', '', { httpOnly: true }).json('ok')
})

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { originalname, path } = req.file
  const parts = originalname.split('.')
  const ext = parts[parts.length - 1]
  const newPath = path + '.' + ext
  fs.renameSync(path, newPath)

  const { token } = req.cookies
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) throw err
    const { title, summary, content } = req.body
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath,
      author: info.id
    })
    res.json(postDoc)
  })
})

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null
  if (req.file) {
    const { originalname, path } = req.file
    const parts = originalname.split('.')
    const ext = parts[parts.length - 1]
    newPath = path + '.' + ext
    fs.renameSync(path, newPath)
  }

  const { token } = req.cookies
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) throw err
    const { id, title, summary, content } = req.body
    const postDoc = await Post.findById(id)
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id)
    if (!isAuthor) {
      return res.status(400).json('You are not the author of this post')
    }
    await postDoc.updateOne({
      title,
      summary,
      content,
      cover: newPath ? newPath : postDoc.cover
    })

    res.json(postDoc)
  })
})

app.get('/post', async (req, res) => {
  res.json(
    await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20)
  )
})

app.get('/post/:id', async (req, res) => {
  const { id } = req.params
  const postDoc = await Post.findById(id).populate('author', ['username'])
  res.json(postDoc)
})

app.delete('/post/:id', authenticateToken, async (req, res) => {
  const { id } = req.params // Post ID to be deleted
  try {
    const post = await Post.findById(id) // Find the post by ID
    if (!post) {
      return res.status(404).json('Post not found')
    }

    // Check if the authenticated user is the author of the post
    if (post.author.toString() !== req.user.id) {
      return res.status(403).json('You can only delete your own posts')
    }

    // Delete the post using the correct method
    await Post.findByIdAndDelete(id) // This will delete the post by its ID

    res.json('Post deleted successfully')
  } catch (error) {
    console.error('Error while deleting post: ', error) // Log error for debugging
    res.status(500).json('Error deleting post')
  }
})

app.listen(5000, () => {
  console.log('Server is running on http://localhost:5000')
})
