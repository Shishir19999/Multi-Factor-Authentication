import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import nodemailer from 'nodemailer';
import randomize from 'randomatic';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((error) => {
  console.error('Error connecting to MongoDB:', error.message);
});

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  otp: String,
});

const User = mongoose.model('User', userSchema);

// Function to send OTP to the user's email
async function sendOtpEmail(email, otp) {
  try {
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT,
            secure: false,
        auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OTP Verification',
      text: `Your OTP is: ${otp}`,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent: ' + info.response);
  } catch (error) {
    console.error('Error sending email:', error.message);
  }
}

// Registration endpoint
app.post('/auth/register', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Check if the email already exists in the database
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email already exists',
        });
      }
  
      // Hash the password before saving it to the database
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create a new user document
      const newUser = new User({ email, password: hashedPassword });
  
      // Save the user to the database
      await newUser.save();
  
      // Include the redirect URL in the response
      return res.json({ success: true, message: 'User registered successfully', redirectTo: '/login' });
    } catch (error) {
      console.error('Error during registration:', error.message);
      return res.status(500).json({
        success: false,
        message: 'An error occurred during registration',
      });
    }
  });
  

// Login endpoint
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    const generatedOtp = randomize('0', 6);
    user.otp = generatedOtp;
    await user.save();

    sendOtpEmail(email, generatedOtp);

    return res.json({ success: true });
  } catch (error) {
    console.error('Error during login:', error.message);
    return res.status(500).json({
      success: false,
      message: 'An error occurred during login',
    });
  }
});

// OTP verification endpoint
app.post('/auth/verify-otp', async (req, res) => {
  const { otp } = req.body;

  try {
    const user = await User.findOne({ otp });

    if (!user) {
      return res.json({ success: false, message: 'Invalid OTP' });
    }

    user.otp = '';
    await user.save();

    return res.json({ success: true });
  } catch (error) {
    console.error('Error during OTP verification:', error.message);
    return res.status(500).json({
      success: false,
      message: 'An error occurred during OTP verification',
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
