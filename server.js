require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());


mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));


const UserSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true,
    trim: true 
  },
  email: { 
    type: String, 
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: { 
    type: String, 
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});


const TaskSchema = new mongoose.Schema({
  title: { 
    type: String, 
    required: true,
    trim: true
  },
  description: { 
    type: String,
    default: '',
    trim: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User'
  },
  completed: {
    type: Boolean,
    default: false
  },
  priority: {
    type: Number,
    enum: [1, 2, 3],
    default: 3
  },
  dueDate: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});


TaskSchema.pre('findOneAndUpdate', function(next) {
  this.set({ updatedAt: new Date() });
  next();
});

const User = mongoose.model("User", UserSchema);
const Task = mongoose.model("Task", TaskSchema);


const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email }, 
    process.env.JWT_SECRET, 
    { expiresIn: "7d" }
  );
};


const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ error: "Access denied" });
  
  try {
    const verified = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};


app.post("/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }
    
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ 
      name, 
      email, 
      password: hashedPassword 
    });
    
    
    const token = generateToken(user);
    res.status(201).json({ 
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Server error during signup" });
  }
});


app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    
    const token = generateToken(user);
    res.json({ 
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});


app.get("/auth/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


app.post("/tasks", authMiddleware, async (req, res) => {
  try {
    const { title, description, priority, dueDate, completed } = req.body;
    
    
    if (!title) {
      return res.status(400).json({ error: "Task title is required" });
    }
    
    
    const task = await Task.create({ 
      title,
      description: description || '',
      priority: priority || 3,
      dueDate: dueDate || null,
      completed: completed || false,
      userId: req.user.id
    });
    
    res.status(201).json(task);
  } catch (err) {
    console.error("Task creation error:", err);
    res.status(500).json({ error: "Failed to create task" });
  }
});


app.get("/tasks", authMiddleware, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.id })
      .sort({ createdAt: -1 });
    res.json(tasks);
  } catch (err) {
    console.error("Task fetch error:", err);
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});


app.get("/tasks/:id", authMiddleware, async (req, res) => {
  try {
    const task = await Task.findOne({ 
      _id: req.params.id, 
      userId: req.user.id 
    });
    
    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }
    
    res.json(task);
  } catch (err) {
    console.error("Task fetch error:", err);
    res.status(500).json({ error: "Failed to fetch task" });
  }
});


app.put("/tasks/:id", authMiddleware, async (req, res) => {
  try {
    const { title, description, priority, dueDate, completed } = req.body;
    
    
    const existingTask = await Task.findOne({ 
      _id: req.params.id, 
      userId: req.user.id 
    });
    
    if (!existingTask) {
      return res.status(404).json({ error: "Task not found" });
    }
    
    
    const task = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { 
        title,
        description,
        priority,
        dueDate,
        completed
      },
      { new: true }
    );
    
    res.json(task);
  } catch (err) {
    console.error("Task update error:", err);
    res.status(500).json({ error: "Failed to update task" });
  }
});


app.patch("/tasks/:id/toggle", authMiddleware, async (req, res) => {
  try {
    const task = await Task.findOne({ 
      _id: req.params.id, 
      userId: req.user.id 
    });
    
    if (!task) {
      return res.status(404).json({ error: "Task not found" });
    }
    
    task.completed = !task.completed;
    await task.save();
    
    res.json(task);
  } catch (err) {
    console.error("Task toggle error:", err);
    res.status(500).json({ error: "Failed to toggle task" });
  }
});


app.delete("/tasks/:id", authMiddleware, async (req, res) => {
  try {
    const result = await Task.deleteOne({ 
      _id: req.params.id, 
      userId: req.user.id 
    });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "Task not found" });
    }
    
    res.json({ message: "Task deleted successfully" });
  } catch (err) {
    console.error("Task deletion error:", err);
    res.status(500).json({ error: "Failed to delete task" });
  }
});


app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));