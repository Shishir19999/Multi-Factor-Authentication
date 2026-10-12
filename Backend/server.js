import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { createApp } from './app.js';
import { logMailStartupChecks } from './mailer.js';
import { bootstrapAdmin } from './lib/bootstrap.js';

dotenv.config();
logMailStartupChecks();

if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET is not set. Add it to Backend/.env');
  process.exit(1);
}

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0'; // reachable from other devices on the LAN

mongoose.connect(process.env.MONGODB_URL).then(async () => {
  console.log('Connected to MongoDB');
  await bootstrapAdmin();
}).catch((error) => {
  console.error('Error connecting to MongoDB:', error.message);
});

createApp().listen(PORT, HOST, () => {
  console.log(`Server is running on http://${HOST}:${PORT}`);
});
